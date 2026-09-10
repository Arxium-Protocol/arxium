#!/usr/bin/env bash
# Partition-and-heal acceptance harness for the finality unwind path.
#
# Boots NUM_VALIDATORS (default 4, minimum 4) local validators from a
# throwaway genesis, cuts one of them off the network, lets both sides
# advance, then heals and checks the isolated node abandons what it built
# alone in favour of the chain the quorum certified.
#
# Why 4 and not 2. Quorum is 2n/3 + 1, so a 1/1 split leaves neither side
# able to finalize: both stall, nothing diverges, and the run proves only
# that a chain with no quorum stops — the quorum-degeneracy point
# scripts/two-node-fault-harness.sh already makes in its header. At n=4
# quorum is 3, so a 3/1 split is asymmetric in exactly the way the unwind
# exists for: the majority keeps finalizing while the isolated node keeps
# producing and locally committing blocks that never finalize. That
# asymmetry is the precondition, and this script refuses to report a pass
# without first proving it actually happened (see "Step 4" below).
#
# Separate script rather than a mode of two-node-fault-harness.sh: that one
# arms a Byzantine node that lies about its own state_root and asserts
# against evidence/adjudication/slashing. Nothing here is Byzantine — every
# node follows the protocol exactly, one just cannot hear the others — and
# none of the stake assertions apply. Same scaffolding, different fault.
#
# HEAL_WHEN selects which unwind path the run aims at — `finalized` (default)
# for the peer-driven recovery, `votes` for arxd/finality's
# enforce_certificate, which is unreachable in the default mode. See the
# HEAL_WHEN block below.
#
# Exit codes:
#   0  pass
#   1  fail — the chain did the wrong thing
#   3  INCONCLUSIVE — the fault never actually landed, so nothing was
#      tested. Distinct on purpose: a partition harness that "heals" a chain
#      which never diverged passes identically to one that works, and a
#      divergence-recovery harness passed for months here while roughly
#      three quarters of its runs never injected the fault at all. A silent
#      no-op run must not be able to look like a real pass.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NUM_VALIDATORS="${NUM_VALIDATORS:-4}"
# Height the isolated node is allowed to start diverging at. Slid forward
# below to a height that is actually its proposer slot.
WARMUP_HEIGHT="${WARMUP_HEIGHT:-6}"
# Ports differ from two-node-fault-harness.sh's (18545/18601) so both
# harnesses can run at once without fighting over listeners.
BASE_RPC_PORT=18645
BASE_P2P_PORT=18701
STARTUP_TIMEOUT=30
# Same reasoning as the fault harness's 240s, one step longer: healing here
# additionally waits out MAX_CONSECUTIVE_SYNC_FAILURES (5) failed sync
# rounds at STATUS_INTERVAL (5s) before divergence recovery is even
# attempted (arxd/network/src/lib.rs), then a Hashes round trip and a
# Certificate round trip on top. Slack, not a tight bound.
CHAIN_TIMEOUT=300

# Which unwind path the run is aiming at. See the "checking the healed node
# unwound" block for why these are not interchangeable.
#
#   finalized  the majority certifies TARGET_H while the victim is still cut
#              off, so the victim can only learn about it from a peer later.
#              Exercises the executor's finality gate and arxd/network's
#              peer-driven recovery.
#   votes      the victim rejoins while the majority is *still voting* on
#              TARGET_H, tallies a quorum for a hash it disagrees with, and
#              unwinds on its own evidence. The only way arxd/finality's
#              enforce_certificate is reachable from a live network.
HEAL_WHEN="${HEAL_WHEN:-finalized}"
case "$HEAL_WHEN" in
    finalized|votes) ;;
    *) echo "HEAL_WHEN must be 'finalized' or 'votes', got '$HEAL_WHEN'" >&2; exit 1 ;;
esac

# Only used by HEAL_WHEN=votes, where it is what makes the window
# deterministic rather than a race. The real timeout is 8s
# (arxd/finality's ROUND_TIMEOUT), and a kill/restart is most of that
# before the victim can receive anything, so at 8s the run would come back
# inconclusive far more often than not. Widening it leaves the majority
# inside round 0 while the restart finishes. Needs a fault-injection build;
# `ensure_fault_injection_allowed` refuses it on a real chain name.
ROUND_TIMEOUT_SECS="${ROUND_TIMEOUT_SECS:-45}"

if [ "$NUM_VALIDATORS" -lt 4 ]; then
    echo "NUM_VALIDATORS must be >= 4: at n<4 a 3/1 split has no quorum on the" >&2
    echo "majority side, so the partition stalls both sides instead of diverging" >&2
    echo "them, and this harness would be testing nothing. See header." >&2
    exit 1
fi

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-partition-harness)"
echo "harness scratch dir: $ROOT (kept either way)"

declare -a DIRS RPC_PORTS P2P_PORTS PIDS ADDRS PEERS
# The node that gets cut off. Last index, so node 0 stays the bootnode.
VICTIM=$((NUM_VALIDATORS - 1))

cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# --release for the same reason two-node-fault-harness.sh documents: the
# debug build trips a libp2p-request-response debug_assert under this
# harness's connection churn often enough to swamp the real signal — and
# this harness deliberately churns connections harder than that one does,
# since partitioning and healing is exactly repeated connect/disconnect.
echo "building arxd with fault-injection (--release; see comment above)..."
cargo build --release -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/release/arxd"

echo "generating $NUM_VALIDATORS node identities and validator keys..."
VALIDATORS='{}'
ACCOUNTS='{}'
# No actions are submitted in this scenario, so funding is not strictly
# needed — kept at the fault harness's level anyway so a future check that
# does submit one doesn't rediscover the silent "insufficient balance for
# the action fee" drop that cost a session there.
ACCOUNT_FUNDING=$((100 * 1000000))
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    PEERS[$i]="$("$BIN" node-key --base-path "${DIRS[$i]}")"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
    ACCOUNTS="$(jq --arg addr "${ADDRS[$i]}" --argjson balance "$ACCOUNT_FUNDING" \
        '. + {($addr): {balance: $balance, nonce: 0, identity_hash: null}}' <(echo "$ACCOUNTS"))"
done

# The victim can only ever produce one block while isolated, and only at one
# specific height: it holds the parent for tip+1 and nothing beyond, and
# advancing a round needs a RoundCertificate, which needs a quorum it does
# not have alone. So tip+1 must land on its own round-0 proposer slot —
# sorted(validator_addresses)[height % n], per
# xc_primitives::eligible_proposer — or it produces nothing and the run is
# inconclusive. Addresses are random every run, so which heights those are is
# only known once the keys exist.
SORTED_ADDRS=($(printf '%s\n' "${ADDRS[@]}" | LC_ALL=C sort))
VICTIM_SLOT=-1
for idx in "${!SORTED_ADDRS[@]}"; do
    if [ "${SORTED_ADDRS[$idx]}" = "${ADDRS[$VICTIM]}" ]; then
        VICTIM_SLOT=$idx
        break
    fi
done

# chain_name must be exactly this: arxd/node's ensure_fault_injection_allowed
# refuses to boot with ARXD_BLOCK_PEERS set on any other chain, so a
# mistyped --chain can never partition a real node.
jq -n --argjson validators "$VALIDATORS" --argjson accounts "$ACCOUNTS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

start_node() {
    # $1 = index, $2... = extra env assignments (unused for honest nodes)
    local i=$1; shift
    # Empty for node 0 (it *is* the bootnode); expanded below in the
    # `${a[@]+...}` form because bash 3.2, which macOS ships, errors on
    # "${a[@]}" for an empty array under `set -u`.
    local bootnode=()
    [ "$i" != 0 ] && bootnode=(--bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}/p2p/${PEERS[0]}")
    # RUST_LOG is not optional here. arxd's tracing subscriber emits *nothing*
    # with it unset, so every grep-based assertion in this script (the unwind
    # line, HALT, the ContradictsCertificate note) reads an empty file and
    # decides whatever an empty file decides. Setting it in the environment
    # rather than trusting the caller's: a harness whose verdict depends on an
    # ambient variable is a harness that reports different results on two
    # machines running the same code.
    # HEAL_WHEN=votes slows every node's round timeout, not just the
    # victim's: it is the *majority* that has to still be in round 0 when
    # the victim finishes restarting.
    local slow_rounds=()
    [ "$HEAL_WHEN" = votes ] && slow_rounds=("ARXD_ROUND_TIMEOUT_SECS=$ROUND_TIMEOUT_SECS")
    env RUST_LOG="${RUST_LOG:-info}" ${slow_rounds[@]+"${slow_rounds[@]}"} "$@" "$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[$i]}" --validator \
        --port "${RPC_PORTS[$i]}" --p2p-port "${P2P_PORTS[$i]}" --rpc-bind 127.0.0.1 \
        ${bootnode[@]+"${bootnode[@]}"} \
        >>"$ROOT/node-$i.log" 2>&1 &
    PIDS[$i]=$!
}

# ponytail: star topology on node 0, matching the fault harness — a
# full-mesh --bootnodes list tripped a libp2p-request-response internal
# assertion there. mDNS connects the rest on localhost anyway, which is also
# precisely why the partition below cannot be done by withholding bootnodes.
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    echo "starting node $i as ${ADDRS[$i]} ..."
    start_node "$i"
done

wait_for_rpc() {
    local port=$1 deadline
    deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$port/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    wait_for_rpc "${RPC_PORTS[$i]}" || { echo "node $i never came up, see $ROOT/node-$i.log" >&2; exit 1; }
done

# Node 0 speaks for the majority side; the victim is queried directly.
RPC_MAJORITY="${RPC_PORTS[0]}"
RPC_VICTIM="${RPC_PORTS[$VICTIM]}"

status_field() { curl -sf "http://127.0.0.1:$1/status" | jq -r ".$2 // 0"; }
# The majority's hash at height H, read as the child's parent_hash: /blocks
# serves the block struct, which has no hash field, and comparing state_roots
# would be wrong here — two empty blocks by different proposers at the same
# height share a state_root while being different blocks.
# Tolerates a 404: HEAL_WHEN=votes polls for this height before the majority
# has built it, and a bare `curl -sf` in a pipefail pipeline exits 22 and
# takes the whole run with it. Empty string means "not there yet".
hash_at() { { curl -sf "http://127.0.0.1:$1/blocks/$(($2 + 1))" || true; } | jq -r '.parent_hash // ""'; }

# Highest tip seen on each majority node, so "never moved backward" is
# checked against every sample taken, not just the two endpoints.
declare -a MAJORITY_PEAK
for i in $(seq 0 $((VICTIM - 1))); do MAJORITY_PEAK[$i]=0; done
sample_majority() {
    local i tip regressed=0
    for i in $(seq 0 $((VICTIM - 1))); do
        tip="$(status_field "${RPC_PORTS[$i]}" tip_height)"
        if [ "$tip" -lt "${MAJORITY_PEAK[$i]}" ]; then
            echo "  FAIL: majority node $i tip went backward: ${MAJORITY_PEAK[$i]} -> $tip"
            regressed=1
        elif [ "$tip" -gt "${MAJORITY_PEAK[$i]}" ]; then
            MAJORITY_PEAK[$i]=$tip
        fi
    done
    return $regressed
}

inconclusive() {
    echo
    echo "$*" >&2
    echo "INCONCLUSIVE $(date -u +%Y-%m-%dT%H:%M:%SZ): $*" > "$ROOT/result"
    echo "INCONCLUSIVE — the partition never produced a divergence, so nothing was" >&2
    echo "tested. This is not a pass. Logs in $ROOT." >&2
    exit 3
}

# --- Partition ---------------------------------------------------------------
#
# First get the set into steady state. A freshly booted node catches up by
# applying whole sync *pages*, so its tip jumps several heights at once —
# TARGET_H - 1 can be skipped over entirely while the fast poll below is
# looking for it, which is what made the first run of this script report
# INCONCLUSIVE against a chain that was working fine. Once the victim is
# level with the majority it advances one gossiped block at a time, which is
# the only regime in which "cut it at exactly this height" is achievable.
echo "waiting for the victim to catch up to the majority (steady state)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
steady=false
while [ "$(date +%s)" -lt "$deadline" ]; do
    sample_majority || true
    majority_tip="$(status_field "$RPC_MAJORITY" tip_height)"
    victim_tip="$(status_field "$RPC_VICTIM" tip_height)"
    majority_watermark="$(status_field "$RPC_MAJORITY" final_watermark)"
    # Watermark > 0 as well as tips level: a majority that has not finalized
    # anything yet has no certificate for the victim to be unwound by later,
    # and `build_sync_response`'s clamp would still be falling back to the
    # tip. Both sides must be past first finality before the cut.
    if [ "$victim_tip" -ge $((majority_tip - 1)) ] \
        && [ "$majority_tip" -ge "$WARMUP_HEIGHT" ] && [ "$majority_watermark" -gt 0 ]; then
        steady=true
        break
    fi
    sleep 1
done
[ "$steady" = true ] \
    || inconclusive "the set never reached steady state (victim tip $victim_tip, majority tip $majority_tip, majority watermark $majority_watermark)"
echo "  steady at victim tip $victim_tip, majority watermark $majority_watermark"

# The victim must be cut off while its tip is exactly TARGET_H - 1, so the one
# height it can produce alone is TARGET_H. The target is picked off the live
# tip, never from a constant: the further ahead it is, the more chances the
# victim has to apply a multi-block sync page and skip straight over the
# height we are waiting for. Nearest own slot at least two heights out, so
# there is one whole block of margin for the fast poll and no more.
#
# Overshooting is retried rather than treated as a verdict — the next slot is
# only NUM_VALIDATORS heights later, and a missed sample says nothing about
# the code under test. Running out of attempts is what makes it inconclusive.
cut_ready=false
for attempt in $(seq 1 "${CUT_ATTEMPTS:-4}"); do
    victim_tip="$(status_field "$RPC_VICTIM" tip_height)"
    TARGET_H=$victim_tip
    while (( TARGET_H < victim_tip + 2 || TARGET_H % NUM_VALIDATORS != VICTIM_SLOT )); do
        TARGET_H=$((TARGET_H + 1))
    done
    echo "attempt $attempt: waiting for the victim to reach $((TARGET_H - 1)) (its slot is $TARGET_H)..."
    deadline=$(($(date +%s) + CHAIN_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        victim_tip="$(status_field "$RPC_VICTIM" tip_height)"
        [ "$victim_tip" -ge $((TARGET_H - 1)) ] && break
        sleep 0.2
    done
    sample_majority || true
    if [ "$victim_tip" -eq $((TARGET_H - 1)) ]; then
        cut_ready=true
        break
    fi
    echo "  overshot to $victim_tip (a sync page crossed $((TARGET_H - 1))); trying the next slot"
done
[ "$cut_ready" = true ] \
    || inconclusive "never caught the victim at a slot boundary in ${CUT_ATTEMPTS:-4} attempts (last tip $victim_tip, wanted $((TARGET_H - 1)))"

echo "partitioning node $VICTIM (blocking peers 0..$((VICTIM - 1))) ..."
BLOCK_LIST="$(IFS=,; echo "${PEERS[*]:0:$VICTIM}")"
kill "${PIDS[$VICTIM]}" 2>/dev/null || true
wait "${PIDS[$VICTIM]}" 2>/dev/null || true
# ponytail: the cut is a restart with ARXD_BLOCK_PEERS rather than a
# firewall rule — pf needs root and mDNS is unconditional in arxd/network's
# Behaviour, so a node restarted with no --bootnodes rediscovers everyone on
# localhost within seconds. Blocking at the swarm level is what the
# bad-gossip ban path already does, and it cuts both directions.
start_node "$VICTIM" "ARXD_BLOCK_PEERS=$BLOCK_LIST"
wait_for_rpc "$RPC_VICTIM" || { echo "victim never came back up, see $ROOT/node-$VICTIM.log" >&2; exit 1; }

echo "waiting for the isolated node to commit height $TARGET_H alone..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    victim_tip="$(status_field "$RPC_VICTIM" tip_height)"
    [ "$victim_tip" -ge "$TARGET_H" ] && break
    sample_majority || true
    sleep 1
done
ISOLATED_HASH="$(curl -sf "http://127.0.0.1:$RPC_VICTIM/status" | jq -r '.tip_hash // ""')"
VICTIM_WATERMARK="$(status_field "$RPC_VICTIM" final_watermark)"

# --- Step 4a: the half of the precondition that holds in both modes ----------
#
# Everything after this only means something if the two sides actually built
# different blocks at the same height. A heal that "recovers" a chain which
# never diverged is indistinguishable from a working one, so each of these
# exits 3 rather than continuing to the recovery assertions.
echo "checking the isolated node built its own block at $TARGET_H (precondition)..."
[ "$victim_tip" -eq "$TARGET_H" ] \
    || inconclusive "isolated node's tip is $victim_tip, expected exactly $TARGET_H — it never produced alone"
[ -n "$ISOLATED_HASH" ] \
    || inconclusive "could not read the isolated node's hash at $TARGET_H"
[ "$VICTIM_WATERMARK" -lt "$TARGET_H" ] \
    || inconclusive "isolated node's watermark is $VICTIM_WATERMARK, not below $TARGET_H — it finalized alone, which means it was never actually isolated"
echo "  ok: isolated node committed $ISOLATED_HASH at $TARGET_H"
echo "  ok: isolated watermark $VICTIM_WATERMARK < $TARGET_H (it committed without finalizing)"

# ponytail: exactly one diverged block, not several. An isolated validator
# can only produce on its own round-0 slot and cannot advance a round
# without a quorum, so it commits TARGET_H and then stalls at TARGET_H + 1
# forever. One block is enough to satisfy the unwind's precondition (tip
# above the watermark, contradicting a certificate); a deeper fork needs
# splitting the set 2/2 with a second quorum, which no single-host harness
# can reach. Add that only if the unwind ever needs to be proven for depth
# > 1.

if [ "$HEAL_WHEN" = finalized ]; then
    # The majority is left alone to certify TARGET_H before the victim comes
    # back, so by the time it reconnects the precommit votes for that height
    # are already deleted (see the unwind check below).
    echo "waiting for the majority to finalize past $TARGET_H..."
    deadline=$(($(date +%s) + CHAIN_TIMEOUT))
    majority_watermark=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        majority_watermark="$(status_field "$RPC_MAJORITY" final_watermark)"
        [ "$majority_watermark" -gt "$TARGET_H" ] && break
        sample_majority || true
        sleep 2
    done
    MAJORITY_HASH="$(hash_at "$RPC_MAJORITY" "$TARGET_H")"
else
    # HEAL_WHEN=votes: the whole point is to heal *before* the majority has
    # built TARGET_H, so it is still gossiping precommits for that height
    # when the victim rejoins. Assert that it really has not yet, or the run
    # is the `finalized` variant wearing this label.
    majority_tip="$(status_field "$RPC_MAJORITY" tip_height)"
    majority_watermark="$(status_field "$RPC_MAJORITY" final_watermark)"
    [ "$majority_tip" -lt "$TARGET_H" ] \
        || inconclusive "majority is already at tip $majority_tip before the heal — round 0's timeout expired while the victim was being cut, so the precommits this variant needs are already in flight or gone. Raise ROUND_TIMEOUT_SECS (currently $ROUND_TIMEOUT_SECS)."
    [ "$majority_watermark" -lt "$TARGET_H" ] \
        || inconclusive "majority watermark is already $majority_watermark before the heal — it finalized $TARGET_H without the victim, which is the \`finalized\` variant"
    echo "  ok: majority still inside round 0 at tip $majority_tip (it has not proposed $TARGET_H yet)"
fi

# --- Heal --------------------------------------------------------------------
echo "healing the partition (restarting node $VICTIM without the block list)..."
kill "${PIDS[$VICTIM]}" 2>/dev/null || true
wait "${PIDS[$VICTIM]}" 2>/dev/null || true
start_node "$VICTIM"
wait_for_rpc "$RPC_VICTIM" || { echo "victim never came back up, see $ROOT/node-$VICTIM.log" >&2; exit 1; }

if [ "$HEAL_WHEN" = votes ]; then
    # Re-checked *after* the restart, not just before it: the restart is the
    # slow part (process boot, RPC up, dial, identify, a gossipsub mesh
    # heartbeat), and gossipsub does not replay. If the majority finalized
    # TARGET_H during those seconds, the votes are deleted, the victim can
    # only be rescued by the peer-driven path, and the run tests the same
    # thing the `finalized` variant already tests. That is a no-op run for
    # this variant's purpose, so it exits 3 rather than passing on the
    # recovery path. Strictly below, not "at or below": a watermark equal to
    # TARGET_H already means TARGET_H is final.
    majority_watermark="$(status_field "$RPC_MAJORITY" final_watermark)"
    [ "$majority_watermark" -lt "$TARGET_H" ] \
        || inconclusive "the majority finalized $TARGET_H (watermark $majority_watermark) while the victim was restarting — its precommits are deleted, so this run is the \`finalized\` variant wearing the \`votes\` label"
    echo "  ok: majority watermark still $majority_watermark < $TARGET_H at the moment of heal"

    echo "waiting for the majority to propose $TARGET_H at round 1 and finalize it..."
    deadline=$(($(date +%s) + CHAIN_TIMEOUT))
    MAJORITY_HASH=""
    majority_watermark=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sample_majority || true
        [ -n "$MAJORITY_HASH" ] || MAJORITY_HASH="$(hash_at "$RPC_MAJORITY" "$TARGET_H")"
        majority_watermark="$(status_field "$RPC_MAJORITY" final_watermark)"
        [ "$majority_watermark" -gt "$TARGET_H" ] && break
        sleep 1
    done
    [ -n "$MAJORITY_HASH" ] || MAJORITY_HASH="$(hash_at "$RPC_MAJORITY" "$TARGET_H")"
fi

# --- Step 4b: divergence itself ---------------------------------------------
echo "checking the partition actually diverged the chain (precondition)..."
[ -n "$MAJORITY_HASH" ] \
    || inconclusive "could not read the majority's hash at $TARGET_H"
[ "$ISOLATED_HASH" != "$MAJORITY_HASH" ] \
    || inconclusive "both sides hold the same block $ISOLATED_HASH at $TARGET_H — the victim heard the majority before the cut landed, so there is no divergence to heal"
[ "$majority_watermark" -gt "$TARGET_H" ] \
    || inconclusive "majority watermark is $majority_watermark, never passed $TARGET_H — the majority stalled instead of finalizing without the victim"
echo "  ok: divergence at $TARGET_H — isolated $ISOLATED_HASH vs majority $MAJORITY_HASH"
echo "  ok: majority watermark $majority_watermark > $TARGET_H (it finalized without the victim)"

CONVERGE_FROM="$(status_field "$RPC_MAJORITY" tip_height)"
echo "waiting for the healed node to converge past $CONVERGE_FROM (timeout ${CHAIN_TIMEOUT}s)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
converged=false
while [ "$(date +%s)" -lt "$deadline" ]; do
    sample_majority || true
    victim_tip="$(status_field "$RPC_VICTIM" tip_height)"
    if [ "$victim_tip" -gt "$CONVERGE_FROM" ]; then converged=true; break; fi
    sleep 2
done

pass=true

echo "checking the healed node unwound its own block..."
# Two different code paths can do this, and they are not interchangeable.
#
#   `finality: certificate for height N names X` is arxd/finality's
#   enforce_certificate — this node tallied a live quorum of precommit
#   votes for a height it holds a different block at, and acted on its own
#   evidence.
#
#   `reverted from height` is arxd/network's peer-driven recovery — this
#   node kept rejecting a peer's blocks, gave up after
#   MAX_CONSECUTIVE_SYNC_FAILURES, and then verified that peer's
#   certificate.
#
# HEAL_WHEN=finalized can only ever take the second: the majority certifies
# TARGET_H while the victim is cut off, and precommit votes are deleted once
# a height finalizes and are never re-gossiped (see recovery.rs's
# BackfillingCertificate note), so no vote for TARGET_H can reach the victim
# afterwards. enforce_certificate is structurally unreachable there, which is
# exactly why HEAL_WHEN=votes exists — and why it insists on the first line
# rather than accepting either. Accepting either would let the peer-driven
# path satisfy a check written to cover enforce_certificate.
finality_line="$(grep -o "finality: certificate for height $TARGET_H names.*" "$ROOT/node-$VICTIM.log" | head -n 1 || true)"
recovery_line="$(grep -o 'reverted from height.*' "$ROOT/node-$VICTIM.log" | head -n 1 || true)"
if [ -n "$finality_line" ]; then
    echo "  ok (finality path): $finality_line"
elif [ "$HEAL_WHEN" = votes ]; then
    if [ -n "$recovery_line" ]; then
        inconclusive "the peer-driven path unwound the victim first ($recovery_line) — enforce_certificate was never reached, so PR #3's code was not exercised. The heal lost the race with MAX_CONSECUTIVE_SYNC_FAILURES; raise ROUND_TIMEOUT_SECS (currently $ROUND_TIMEOUT_SECS)."
    fi
    echo "  FAIL: healed node never unwound (tip $victim_tip); last lines:"
    tail -n 30 "$ROOT/node-$VICTIM.log"
    pass=false
elif [ -n "$recovery_line" ]; then
    echo "  ok (recovery path): $recovery_line"
else
    echo "  FAIL: healed node never unwound (tip $victim_tip); last lines:"
    tail -n 30 "$ROOT/node-$VICTIM.log"
    pass=false
fi

if [ "$converged" != true ]; then
    echo "  FAIL: healed node stalled at tip $victim_tip, majority was at $CONVERGE_FROM after the heal"
    pass=false
fi

echo "checking the healed node now holds the majority's block at $TARGET_H..."
healed_hash="$(hash_at "$RPC_VICTIM" "$TARGET_H")"
if [ "$healed_hash" = "$MAJORITY_HASH" ]; then
    echo "  ok: node $VICTIM agrees with the majority at $TARGET_H ($MAJORITY_HASH)"
else
    echo "  FAIL: node $VICTIM holds '$healed_hash' at $TARGET_H, majority holds '$MAJORITY_HASH'"
    pass=false
fi

# The block it built alone must be gone, not merely outranked. by-hash is
# the direct question: a 404 means it is not in this node's chain at any
# height.
echo "checking the block it built alone is no longer committed anywhere..."
orphan_status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RPC_VICTIM/blocks/by-hash/$ISOLATED_HASH")"
if [ "$orphan_status" = "404" ]; then
    echo "  ok: $ISOLATED_HASH is not in node $VICTIM's chain"
else
    echo "  FAIL: node $VICTIM still serves its orphaned block $ISOLATED_HASH (http $orphan_status)"
    pass=false
fi

# The unwind is not allowed to be undone a few seconds later by the node
# re-accepting its own block off its mempool or a stale gossip copy. The
# executor's ContradictsCertificate guard is what refuses that; log it if it
# fired, but assert on the state, which holds whether or not the message was
# logged at the configured level.
echo "checking the old block is not re-accepted once things settle..."
settle_deadline=$(($(date +%s) + 20))
while [ "$(date +%s)" -lt "$settle_deadline" ]; do sample_majority || true; sleep 2; done
resettled_hash="$(hash_at "$RPC_VICTIM" "$TARGET_H")"
orphan_status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RPC_VICTIM/blocks/by-hash/$ISOLATED_HASH")"
if [ "$resettled_hash" = "$MAJORITY_HASH" ] && [ "$orphan_status" = "404" ]; then
    echo "  ok: still on the majority's block at $TARGET_H after settling"
else
    echo "  FAIL: node $VICTIM drifted back after converging (hash '$resettled_hash', orphan http $orphan_status)"
    pass=false
fi
if grep -q "refusing to commit against finality" "$ROOT/node-$VICTIM.log"; then
    echo "  note: the ContradictsCertificate guard fired — its own block was re-offered and refused"
fi

echo "checking no majority node's tip ever moved backward..."
if sample_majority; then
    echo "  ok: majority tips only advanced (peaks: ${MAJORITY_PEAK[*]})"
else
    pass=false
fi

echo "checking no node halted below its watermark..."
halted=0
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    if grep -q "HALT:" "$ROOT/node-$i.log"; then
        echo "  FAIL: node $i halted:"
        grep -m 1 "HALT:" "$ROOT/node-$i.log"
        halted=1
        pass=false
    fi
done
[ "$halted" = 0 ] && echo "  ok: no node halted"

if [ "$pass" = true ]; then
    echo
    if [ "$HEAL_WHEN" = votes ]; then
        echo "PASS — the partition diverged the chain at $TARGET_H, and the isolated"
        echo "node rejoined while the majority was still voting: it tallied a quorum"
        echo "for a hash it disagreed with and unwound on its own evidence"
        echo "(arxd/finality's enforce_certificate), without waiting for a peer."
    else
        echo "PASS — the partition diverged the chain at $TARGET_H, the majority"
        echo "finalized without the isolated node, and on healing that node unwound its"
        echo "own committed block and converged on the certified chain."
    fi
    # Kept, not deleted: the fault harness lost a session to comparing a run
    # against logs that had already been cleaned up.
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "logs and RPC captures kept in $ROOT"
    exit 0
else
    echo
    echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "FAIL — see logs in $ROOT."
    exit 1
fi
