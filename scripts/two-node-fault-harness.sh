#!/usr/bin/env bash
# N-validator acceptance harness for the block-divergence fault loop (see
# Implementation_log's evidence/adjudication sections and docs/runbook.md).
#
# Boots NUM_VALIDATORS (default 4) local validators from a throwaway genesis:
# node 0 is built with `--features fault-injection` and armed to corrupt its
# own signed state_root at FAULT_HEIGHT; the rest are honest. The honest
# majority's independent re-execution must disagree with node 0's block and
# write fault evidence, and an honest node's auto-submitted
# SubmitExecutionFault must slash and tombstone node 0 (BlockDivergence
# adjudication is back on since PR #45, Trello 72/179). Node 0's block never
# certifies — the honest set times its round out and keeps another block at
# FAULT_HEIGHT — so that kept block must not read "disputed". Node 0 must
# never land a counter-slash against an honest validator either. This
# exercises three separate guards against real processes instead of one test
# binary, and only two of them are actually checked below:
#   - Culprit resolution — checked: node 0 tombstoned, honest stakes kept.
#   - Self-incrimination (node 0 must not *submit* a fault action naming an
#     honest validator) — checked at the action level below, by scanning
#     mined blocks for a `SubmitExecutionFault` sent by node 0.
#   - Recursion guard (a fault nested inside a fault) — NOT exercised by
#     this scenario at all; nothing here ever produces a fault-inside-a-fault
#     to trip it. If it ever failed, expect a node dying on stack exhaustion,
#     not a stake or action-level symptom — this harness would not catch it.
#
# ponytail: node 0's /evidence directory being non-empty is not itself proof
# of anything — once dissent actually propagates over gossip (needs a real
# n-validator run, not the mocked single-process tests), node 0 legitimately
# accumulates local copies of the *honest* validators' dissent artifacts
# too. Its evidence-watcher fires on any `ExecutionDisagreement` it locally
# observes, regardless of who authored the underlying dissent
# (core/evidence/src/lib.rs:352). An earlier version of this harness
# asserted that directory was empty and failed the first time a run
# actually completed with full dissent propagation — removed in favor of
# the action-level self-incrimination check below, which tests the actual
# property (nothing submitted, not nothing observed).
#
# NUM_VALIDATORS matters: quorum is 6,667 of 10,000 voting power, so at n=2 (5,000 each) the faulty node's
# own vote is required for any quorum and the chain cannot advance past the
# disputed height at all — that's a quorum degeneracy, not evidence that
# reorg/rollback is required. Default here is 4 (quorum 3, faulty node
# outvoted) so a stall demonstrates an actual missing-machinery gap instead.
#
# FAULT_KIND=prevote (D-26) swaps the fault: node 0 stays an honest proposer
# but, at FAULT_HEIGHT, gossips a second prevote for a made-up block next to
# its real one (ARXD_DOUBLE_PREVOTE_AT_HEIGHT). The honest nodes' tallies
# must catch it and a Fault::PrevoteEquivocation artifact must slash and
# tombstone node 0. Nothing diverges in that mode, so the settlement and
# rollback checks (block-divergence only) are skipped.
#
# What this does NOT prove: the loop working against an ordinary
# hundred-action block. This chain never carries other traffic, so
# artifact_json stays tiny regardless of the compression work already
# landed. It proves the logic, not production load.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NUM_VALIDATORS="${NUM_VALIDATORS:-4}"
FAULT_HEIGHT="${FAULT_HEIGHT:-5}"
FAULT_KIND="${FAULT_KIND:-divergence}"
case "$FAULT_KIND" in
    # Node 0 runs the current build, so the chain classes the dispute Attack;
    # the dispute checks run, then this kind carries on to its own rollback checks.
    divergence) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; EXPECT_CAUSE=Attack; CONTINUE_AFTER=1 ;;
    prevote) FAULT_ENV="ARXD_DOUBLE_PREVOTE_AT_HEIGHT" ;;
    # Build-provenance classification of an upheld dispute (Trello 202):
    # same injected fault, but node 0 stamps its blocks with FAULT_BUILD_ID
    # and genesis lists canonical_builds [OLD_BUILD, <this binary's version>].
    dispute-bug) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; FAULT_BUILD_ID="old-build"; EXPECT_CAUSE=Bug ;;
    dispute-attack) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; FAULT_BUILD_ID=""; EXPECT_CAUSE=Attack ;;
    dispute-unlisted) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; FAULT_BUILD_ID="unlisted-build"; EXPECT_CAUSE=Attack ;;
    # The same, then governance closes the dispute: an honest-validator
    # ResolveDispute proposal, votes, execution after the voting window, and
    # for an Attack a ReinstateValidator proposal that lifts the tombstone.
    resolve-attack) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; FAULT_BUILD_ID=""; EXPECT_CAUSE=Attack; RESOLVE=1 ;;
    resolve-bug) FAULT_ENV="ARXD_INJECT_FAULT_AT_HEIGHT"; FAULT_BUILD_ID="old-build"; EXPECT_CAUSE=Bug; RESOLVE=1 ;;
    *) echo "FAULT_KIND must be divergence, prevote, dispute-bug, dispute-attack, dispute-unlisted, resolve-attack or resolve-bug" >&2; exit 1 ;;
esac
BASE_RPC_PORT=18545
BASE_P2P_PORT=18601
STARTUP_TIMEOUT=30
# The old 58s figure ((CONFIRM_HEIGHT+3)*2+30) was sized for the no-dispute
# case and left no real margin for the one this harness exists to test:
# recovering from the injected fault costs at least one `ROUND_TIMEOUT`
# (arxd/finality/src/lib.rs, 8s in a real build) plus real libp2p gossip
# propagation, not the instant in-process delivery the unit tests get. That
# undertimed the actual disputed-height case often enough to read as a
# stall — confirmed by rerunning the same scenario at 240s with zero
# timeouts across 10 straight attempts, versus a majority of triggered runs
# timing out at 58s. 240s flat, not a tighter formula: the point is enough
# slack for however many round-timeout cycles a real run needs, not the
# tightest bound that happens to work today.
CHAIN_TIMEOUT=240

if [ "$NUM_VALIDATORS" -lt 2 ]; then
    echo "NUM_VALIDATORS must be >= 2" >&2
    exit 1
fi

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-fault-harness)"
echo "harness scratch dir: $ROOT (kept either way)"

declare -a DIRS RPC_PORTS P2P_PORTS PIDS ADDRS
PID_A=""  # index 0's pid, kept named for cleanup clarity

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

# --release is not just for speed: the debug build hits a debug_assert in
# libp2p-request-response's connection-close handling (upstream rust-libp2p
# #4773 / #6601, both open, both confirmed debug_assert) at roughly a 40%
# rate under this harness's connection churn — enough to make most debug
# runs report a stall or crash that has nothing to do with this chain's own
# logic. Release compiles that check out. It does not fix the underlying
# inconsistent connection state upstream is tracking, only this harness's
# ability to get a signal past it — see docs/runbook.md.
echo "building arxd with fault-injection (--release; see comment above)..."
cargo build --release -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/release/arxd"
if [ -n "${RESOLVE:-}" ]; then
    cargo build --release -p send-tx >>"$ROOT/build.log" 2>&1 \
        || { echo "send-tx build failed, see $ROOT/build.log" >&2; exit 1; }
    SEND_TX="$REPO_ROOT/target/release/send-tx"
fi

echo "generating $NUM_VALIDATORS node identities and validator keys..."
VALIDATORS='{}'
ACCOUNTS='{}'
# Genesis validators have stake but, absent this, zero spendable balance —
# every action (including a validator's own SubmitExecutionFault) costs
# ACTION_FEE (arxd/runtime/src/lib.rs:417, 1,000,000 IUM), so with no
# balance every evidence submission gets silently dropped at dispatch
# ("insufficient balance for the action fee"), not just deduped. This
# funded every honest evidence-report attempt into the same nonce-0 mempool
# slot forever and looked identical to a resubmission-storm bug. 100x the
# fee is comfortably more than a short test run needs.
ACCOUNT_FUNDING=$((1000 * 1000000000))  # the metered fee is now ~5e9 IUM per action
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
    ACCOUNTS="$(jq --arg addr "${ADDRS[$i]}" --argjson balance "$ACCOUNT_FUNDING" \
        '. + {($addr): {balance: $balance, nonce: 0, identity_hash: null}}' <(echo "$ACCOUNTS"))"
done
PEER_0="$("$BIN" node-key --base-path "${DIRS[0]}")"

# ponytail: the proposer for a height is sorted(validator_addresses)[height %
# n] (core/primitives/src/consensus.rs's eligible_proposer), and validator
# addresses are freshly random every run — so a fixed FAULT_HEIGHT has only a
# 1/n chance of ever landing on node 0's turn at round 0. Slide FAULT_HEIGHT
# forward (keeping it >= the requested value) to the next height where node
# 0 is actually the round-0 proposer, so the corruption branch in
# arxd/node/src/produce.rs is guaranteed to fire instead of silently never
# triggering (see Implementation_log's write-up of the run this fixes).
SORTED_ADDRS=($(printf '%s\n' "${ADDRS[@]}" | LC_ALL=C sort))
NODE0_SLOT=-1
for idx in "${!SORTED_ADDRS[@]}"; do
    if [ "${SORTED_ADDRS[$idx]}" = "${ADDRS[0]}" ]; then
        NODE0_SLOT=$idx
        break
    fi
done
while (( FAULT_HEIGHT % NUM_VALIDATORS != NODE0_SLOT )); do
    FAULT_HEIGHT=$((FAULT_HEIGHT + 1))
done
CONFIRM_HEIGHT=$((FAULT_HEIGHT + 6))

# Default ChainParams from the binary itself, so only canonical_builds is set
# here (a partial `params` object would not parse).
CURRENT_BUILD="$("$BIN" --version | awk '{print $2}')"
PARAMS="$("$BIN" chain-spec --chain local | jq --arg cur "$CURRENT_BUILD" \
    '.params | .canonical_builds = ["old-build", $cur] | .voting_period_blocks = 10')"
jq -n --argjson validators "$VALIDATORS" --argjson accounts "$ACCOUNTS" --argjson params "$PARAMS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: [],
    params: $params
}' > "$ROOT/genesis.json"

echo "starting node 0 ($FAULT_KIND fault at height $FAULT_HEIGHT) as ${ADDRS[0]} ..."
# RUST_LOG explicitly, not from the caller's environment: arxd's tracing
# subscriber emits nothing at all with it unset, so the log greps below
# ("reverted from height", "HALT:") read an empty file and the run's verdict
# silently depends on whoever's shell started it. Found while building
# scripts/partition-heal-harness.sh.
env RUST_LOG="${RUST_LOG:-info}" "$FAULT_ENV=$FAULT_HEIGHT" \
    ${FAULT_BUILD_ID:+ARXD_FAULT_BUILD_ID=$FAULT_BUILD_ID} \
"$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[0]}" --validator \
    --port "${RPC_PORTS[0]}" --p2p-port "${P2P_PORTS[0]}" --rpc-bind 127.0.0.1 \
    >"$ROOT/node-0.log" 2>&1 &
PIDS[0]=$!
PID_A="${PIDS[0]}"

# ponytail: bootnode everyone to node 0 only (star), matching the original
# two-node script's pattern. A full-mesh --bootnodes list was tried and
# tripped a libp2p-request-response 0.29.0 internal assertion panic
# (duplicate dial via explicit bootnode + mDNS racing) — see
# Implementation_log's write-up of this run. Revisit full-mesh only after
# that's understood; mDNS already connects the rest on localhost.
for i in $(seq 1 $((NUM_VALIDATORS - 1))); do
    echo "starting node $i (honest) as ${ADDRS[$i]} ..."
    RUST_LOG="${RUST_LOG:-info}" \
    "$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[$i]}" --validator \
        --port "${RPC_PORTS[$i]}" --p2p-port "${P2P_PORTS[$i]}" --rpc-bind 127.0.0.1 \
        --bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}/p2p/$PEER_0" \
        >"$ROOT/node-$i.log" 2>&1 &
    PIDS[$i]=$!
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

# Query an honest node (index 1) for chain progress and post-run assertions —
# node 0 is the faulty one and its own view of the chain isn't the one that matters.
RPC_HONEST="${RPC_PORTS[1]}"

echo "waiting for chain to pass height $CONFIRM_HEIGHT (timeout ${CHAIN_TIMEOUT}s)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
tip=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    tip="$(curl -sf "http://127.0.0.1:$RPC_HONEST/status" | jq -r '.tip_height // 0')"
    [ "$tip" -ge "$CONFIRM_HEIGHT" ] && break
    sleep 2
done
if [ "$tip" -lt "$CONFIRM_HEIGHT" ]; then
    echo "FAIL: honest node only reached height $tip, expected >= $CONFIRM_HEIGHT" >&2
    for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
        echo "--- node $i log (tail) ---" >&2; tail -n 40 "$ROOT/node-$i.log" >&2
    done
    exit 1
fi
echo "chain reached height $tip"

pass=true

# --- Dispute classification (dispute-* kinds) --------------------------------
# An upheld dispute slashes no one until governance resolves it, so the
# checks are: the chain upheld it, classed it by provenance, paused
# settlement, and left node 0 un-tombstoned and every honest node unhurt.
if [ -n "${EXPECT_CAUSE:-}" ]; then
    echo "waiting for an upheld dispute classed $EXPECT_CAUSE (timeout ${CHAIN_TIMEOUT}s)..."
    deadline=$(($(date +%s) + CHAIN_TIMEOUT))
    upheld=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        upheld="$(grep -h "execution dispute upheld" "$ROOT"/node-[1-9]*.log 2>/dev/null | head -n 1 || true)"
        [ -n "$upheld" ] && break
        sleep 2
    done
    if [ -z "$upheld" ]; then
        echo "  FAIL: no execution dispute was ever upheld"; pass=false
    elif echo "$upheld" | grep -q "cause.*Some($EXPECT_CAUSE)"; then
        echo "  ok: dispute upheld, cause $EXPECT_CAUSE"
    else
        echo "  FAIL: expected cause $EXPECT_CAUSE, got: $upheld"; pass=false
    fi
    rpc() { curl -sf "http://127.0.0.1:$RPC_HONEST/$1" || echo '{}'; }
    node_status() { rpc "validators/${ADDRS[$1]}" | jq -r 'if (.status|type)=="string" then .status else (.status // {} | keys[0]) end // "none"'; }
    stake_of_node() { rpc "accounts/${ADDRS[$1]}/stake" | jq -r '.active_amount // 0'; }
    open_h="$(rpc status | jq -r '.open_dispute_height // empty')"
    if [ -n "$open_h" ]; then echo "  ok: settlement paused below height $open_h"
    else echo "  FAIL: /status shows no open_dispute_height"; pass=false; fi
    for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
        status="$(rpc "validators/${ADDRS[$i]}" | jq -r 'if (.status|type)=="string" then .status else (.status|keys[0]) end // "none"')"
        if [ "$status" = Tombstoned ]; then
            echo "  FAIL: node $i is Tombstoned before any resolution"; pass=false
        fi
    done
    echo "  ok: nobody tombstoned by the dispute itself"
    chain_cause="$(rpc status | jq -r '.open_dispute_cause // empty')"
    if [ "$chain_cause" = "$EXPECT_CAUSE" ]; then echo "  ok: /status reports open_dispute_cause $chain_cause"
    else echo "  FAIL: /status open_dispute_cause '$chain_cause', expected $EXPECT_CAUSE"; pass=false; fi

    if [ -n "${RESOLVE:-}" ] && [ "$pass" = true ]; then
        # Honest validators 1..n-1 act; node 0 is the accused. Three of four
        # is 7,500 of 10,000 power, over the 5,000 quorum.
        HONEST=$(seq 1 $((NUM_VALIDATORS - 1)))
        tx() { # tx <node index> <send-tx args...>; fails the run if the node refuses it
            local who=$1; shift
            "$SEND_TX" --from "$(cat "${DIRS[$who]}/validator.key")" \
                --node "127.0.0.1:${RPC_PORTS[1]}" "$@" >>"$ROOT/send-tx.log" 2>&1 \
                || { echo "  FAIL: send-tx $* from node $who was refused, see $ROOT/send-tx.log"; return 1; }
        }
        nonce_of() { rpc "accounts/$1" | jq -r '.nonce // 0'; }
        landed() { # landed <node index> <nonce before>: wait for that sender's action to mine
            local deadline=$(($(date +%s) + 60))
            while [ "$(date +%s)" -lt "$deadline" ]; do
                [ "$(nonce_of "${ADDRS[$1]}")" -gt "$2" ] && return 0
                sleep 1
            done
            echo "  FAIL: node $1's action never mined"; return 1
        }
        run_proposal() { # run_proposal <proposal id> <propose args...>: propose, all honest vote, wait out the window, execute
            local id=$1; shift
            local n0 tip0
            n0="$(nonce_of "${ADDRS[1]}")"
            tip0="$(rpc status | jq -r '.tip_height')"
            tx 1 "$@" && landed 1 "$n0" || return 1
            for i in $HONEST; do
                n0="$(nonce_of "${ADDRS[$i]}")"
                tx "$i" --action vote --proposal "$id" --approve true && landed "$i" "$n0" || return 1
            done
            # voting_period_blocks is 10 in genesis; execution needs the window over.
            local deadline=$(($(date +%s) + CHAIN_TIMEOUT))
            while [ "$(rpc status | jq -r '.tip_height')" -lt $((tip0 + 14)) ]; do
                [ "$(date +%s)" -lt "$deadline" ] || { echo "  FAIL: chain stalled waiting out the voting window"; return 1; }
                sleep 2
            done
            n0="$(nonce_of "${ADDRS[2]}")"
            tx 2 --action execute-proposal --proposal "$id" && landed 2 "$n0"
        }

        dispute_h="$(rpc status | jq -r '.open_dispute_height')"
        dispute_header="$(rpc status | jq -r '.open_dispute_header')"
        stake0_before="$(stake_of_node 0)"
        echo "resolving the dispute at height $dispute_h as $EXPECT_CAUSE through governance..."
        if run_proposal 0 --action propose-resolve-dispute --height "$dispute_h" \
                --header "$dispute_header" --cause "$(echo "$EXPECT_CAUSE" | tr A-Z a-z)"; then
            deadline=$(($(date +%s) + 60)); open_h="$dispute_h"
            while [ "$(date +%s)" -lt "$deadline" ]; do
                open_h="$(rpc status | jq -r '.open_dispute_height // empty')"
                [ -z "$open_h" ] && break
                sleep 2
            done
            if [ -z "$open_h" ]; then echo "  ok: dispute closed, settlement may resume"
            else echo "  FAIL: dispute still open at height $open_h after the proposal executed"; pass=false; fi

            status0="$(node_status 0)"
            stake0_after="$(stake_of_node 0)"
            if [ "$EXPECT_CAUSE" = Attack ]; then
                if [ "$status0" = Tombstoned ] && [ "$stake0_after" -lt "$stake0_before" ]; then
                    echo "  ok: node 0 tombstoned and slashed ($stake0_before -> $stake0_after)"
                else
                    echo "  FAIL: Attack verdict left node 0 '$status0', stake $stake0_before -> $stake0_after"; pass=false
                fi
                # A tombstone lifted by governance: the determinism-bug escape hatch.
                echo "reinstating node 0 through governance..."
                if run_proposal 1 --action propose-reinstate --validator "${ADDRS[0]}"; then
                    deadline=$(($(date +%s) + 60)); status0="Tombstoned"
                    while [ "$(date +%s)" -lt "$deadline" ]; do
                        status0="$(node_status 0)"
                        [ "$status0" != Tombstoned ] && break
                        sleep 2
                    done
                    if [ "$status0" != Tombstoned ]; then echo "  ok: node 0 reinstated (status now '$status0')"
                    else echo "  FAIL: node 0 still Tombstoned after the reinstate proposal"; pass=false; fi
                else
                    pass=false
                fi
            else
                if [ "$status0" != Tombstoned ] && [ "$stake0_after" -eq "$stake0_before" ]; then
                    echo "  ok: Bug verdict slashed no one (node 0 '$status0', stake $stake0_after)"
                else
                    echo "  FAIL: Bug verdict hit node 0: '$status0', stake $stake0_before -> $stake0_after"; pass=false
                fi
            fi
        else
            pass=false
        fi
    fi

    if [ -z "${CONTINUE_AFTER:-}" ]; then
        if [ "$pass" = true ]; then
            echo; echo "PASS — $FAULT_KIND: upheld dispute classed $EXPECT_CAUSE by build provenance${RESOLVE:+, resolved through governance}."
            echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"; echo "logs kept in $ROOT"; exit 0
        fi
        echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"; echo "FAIL — see $ROOT"; exit 1
    fi
fi

# Waited on, not read once: the honest fault action lands a few blocks after
# the dispute, not necessarily by the time the chain passes CONFIRM_HEIGHT.
node0_status=""
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
[ -z "${CONTINUE_AFTER:-}" ] && echo "waiting for node 0 to be tombstoned (timeout ${CHAIN_TIMEOUT}s)..."
while [ -z "${CONTINUE_AFTER:-}" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    node0_status="$({ curl -sf "http://127.0.0.1:$RPC_HONEST/validators/${ADDRS[0]}" || echo '{}'; } | jq -r '.status // empty')"
    [ "$node0_status" = "Tombstoned" ] && break
    sleep 2
done
tip="$(curl -sf "http://127.0.0.1:$RPC_HONEST/status" | jq -r '.tip_height // 0')"
# 404-tolerant reads: a tombstoned validator's stake row may be gone, and a
# bare `curl -sf` exits 22 under pipefail and takes the whole run with it.
rpc() { curl -sf "http://127.0.0.1:$RPC_HONEST/$1" || echo '{}'; }
stake_of() { rpc "accounts/$1/stake" | jq -r '.active_amount // 0'; }

# An upheld dispute (divergence) tombstones no one until governance resolves
# it; that is asserted above. Only a double-sign tombstones on the spot.
if [ -z "${CONTINUE_AFTER:-}" ]; then
echo "checking node 0 was slashed and tombstoned..."
node0_stake="$(stake_of "${ADDRS[0]}")"
honest_stake="$(stake_of "${ADDRS[1]}")"
if [ "$node0_status" = "Tombstoned" ] && [ "$node0_stake" -lt "$honest_stake" ]; then
    echo "  ok: node 0 is Tombstoned, stake $node0_stake (honest node 1: $honest_stake)"
else
    echo "  FAIL: node 0 status '${node0_status:-none}', stake $node0_stake (honest node 1: $honest_stake)"
    pass=false
fi
fi

echo "checking no honest validator was slashed..."
for i in $(seq 1 $((NUM_VALIDATORS - 1))); do
    status="$(rpc "validators/${ADDRS[$i]}" | jq -r '.status // "none"')"
    stake="$(stake_of "${ADDRS[$i]}")"
    if [ "$status" != "Tombstoned" ] && [ "$status" != "Jailed" ] && [ "$stake" -gt 0 ]; then
        echo "  ok: node $i keeps its stake ($stake, status $status)"
    else
        echo "  FAIL: node $i was hit: status $status, stake $stake"
        pass=false
    fi
done

# The dispute names node 0's header, not the height: the block the chain kept
# at FAULT_HEIGHT is the honest one and must still settle normally.
if [ "$FAULT_KIND" = divergence ]; then
echo "checking the kept block at height $FAULT_HEIGHT is not marked disputed..."
settlement="$(rpc "blocks/$FAULT_HEIGHT" | jq -r '.settlement // "missing"')"
if [ "$settlement" != "disputed" ] && [ "$settlement" != "missing" ]; then
    echo "  ok: height $FAULT_HEIGHT settlement is $settlement"
else
    echo "  FAIL: height $FAULT_HEIGHT settlement is $settlement"
    pass=false
fi
fi

# Genesis sets no ChainParams, so the window is the default 86,400 blocks —
# this only fails if the action never landed at all, which the tombstone
# check above would already show; kept to report where it landed.
CHALLENGE_WINDOW=86400
echo "checking an honest SubmitExecutionFault landed inside the challenge window..."
fault_height=""
for h in $(seq "$FAULT_HEIGHT" "$tip"); do
    hits="$(rpc "blocks/$h" \
        | jq --arg addr "${ADDRS[0]}" '[.actions[]? | select(.sender != $addr) | select(.payload_json | objects | has("SubmitExecutionFault"))] | length')"
    if [ "${hits:-0}" -gt 0 ]; then fault_height=$h; break; fi
done
if [ -n "$fault_height" ] && [ "$fault_height" -le $((FAULT_HEIGHT + CHALLENGE_WINDOW)) ]; then
    echo "  ok: landed at height $fault_height ($((fault_height - FAULT_HEIGHT)) block(s) after the fault)"
else
    echo "  FAIL: no honest SubmitExecutionFault found in heights $FAULT_HEIGHT..$tip"
    pass=false
fi

echo "checking an honest node submitted fault evidence..."
evidence_honest="$(curl -sf "http://127.0.0.1:$RPC_HONEST/evidence")"
if [ "$FAULT_KIND" = prevote ]; then
    evidence_honest="$(echo "$evidence_honest" | jq '[.[] | select(contains("-prevote-equivocation-"))]')"
fi
if [ "$(echo "$evidence_honest" | jq 'length')" -gt 0 ]; then
    echo "  ok: honest node's evidence dir has $(echo "$evidence_honest" | jq 'length') artifact(s)"
else
    echo "  FAIL: no honest node ever wrote a fault-evidence artifact"
    pass=false
fi

# The actual self-incrimination property: node 0 must never *submit* a
# SubmitExecutionFault action (any sender may submit one — see
# ActionPayload::SubmitExecutionFault's doc comment — but in this scenario
# only node 0 has diverged, so any such action node 0 sends can only be a
# false accusation; a correct node re-adjudicates locally before submitting
# and refuses to name someone else when it itself is culpable — see
# arxd/node/src/lib.rs's build_execution_fault_action). Checked at the
# action level, not via node 0's /evidence directory (see the ponytail
# above this script's header comment for why that directory proves nothing).
echo "checking node 0 never submitted a fault action naming another validator (self-incrimination guard)..."
self_incrimination=0
for h in $(seq 1 "$tip"); do
    block="$(curl -sf "http://127.0.0.1:$RPC_HONEST/blocks/$h")"
    hits="$(echo "$block" | jq --arg addr "${ADDRS[0]}" '[.actions[]? | select(.sender == $addr) | select(.payload_json | objects | has("SubmitExecutionFault"))]')"
    if [ "$(echo "$hits" | jq 'length')" -gt 0 ]; then
        echo "  FAIL: node 0 submitted a SubmitExecutionFault action at height $h: $hits"
        self_incrimination=1
        pass=false
    fi
done
if [ "$self_incrimination" = 0 ]; then
    echo "  ok: node 0 never submitted a fault action"
fi

if [ "$FAULT_KIND" = prevote ]; then
    if [ "$pass" = true ]; then
        echo; echo "PASS — double-prevoting node 0 slashed and tombstoned, honest validators untouched."
        echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
        echo "logs and RPC captures kept in $ROOT"
        exit 0
    fi
    echo; echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "FAIL — see $ROOT for logs and RPC captures."
    exit 1
fi

# --- Divergence recovery -----------------------------------------------------
#
# The injected fault is a genuine divergence, not just a bad block: node 0
# commits its own corrupted block at FAULT_HEIGHT, the honest majority times the
# round out and finalizes a different block at that same height, and from then
# on node 0 rejects every block the majority serves because the parent hash
# never matches. Before divergence recovery existed this is exactly where node 0
# stopped forever with "needs manual intervention" in its log.
#
# A partition-and-heal split can't produce this on a single validator set —
# neither side of a 2+2 split can reach quorum, so neither advances and nothing
# diverges (the quorum-degeneracy point in this script's header). The
# fault-injection path is the scenario the machinery actually has to survive,
# and it is already running above.
#
# Four assertions, not one, because three of the four failure modes here are
# silent: converging on the wrong height, converging on a different state, and
# losing the reverted blocks' actions all look like success from the outside.
echo
echo "checking the diverged node recovered by rolling back..."
RPC_FAULTY="${RPC_PORTS[0]}"

echo "waiting for node 0 to catch back up to the honest chain (timeout ${CHAIN_TIMEOUT}s)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
faulty_tip=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    faulty_tip="$(curl -sf "http://127.0.0.1:$RPC_FAULTY/status" | jq -r '.tip_height // 0')"
    [ "$faulty_tip" -ge "$CONFIRM_HEIGHT" ] && break
    sleep 2
done

# 1. It rolled its block back at all. Two paths can do it: finality unwinds
#    its round-0 block once the round is certified timed out (the usual one
#    now, before any peer serves a conflicting chain), or sync reverts to a
#    peer's certified chain.
if grep -qE "unwinding to|reverted from height" "$ROOT/node-0.log"; then
    echo "  ok: $(grep -oE '(unwinding to|reverted from height).*' "$ROOT/node-0.log" | head -n 1)"
else
    echo "  FAIL: node 0 never reverted (tip $faulty_tip); last lines:"
    tail -n 20 "$ROOT/node-0.log"
    pass=false
fi

# 2. It converged on the majority's chain, byte for byte — same block hash and
#    same state root at the same height, read from both nodes independently.
honest_block="$(curl -sf "http://127.0.0.1:$RPC_HONEST/blocks/$CONFIRM_HEIGHT" || echo '{}')"
faulty_block="$(curl -sf "http://127.0.0.1:$RPC_FAULTY/blocks/$CONFIRM_HEIGHT" || echo '{}')"
honest_root="$(echo "$honest_block" | jq -r '.state_root // "honest-missing"')"
faulty_root="$(echo "$faulty_block" | jq -r '.state_root // "faulty-missing"')"
if [ "$honest_root" = "$faulty_root" ]; then
    echo "  ok: node 0 agrees with the majority at height $CONFIRM_HEIGHT (state_root $honest_root)"
else
    echo "  FAIL: state roots differ at height $CONFIRM_HEIGHT: honest $honest_root vs node 0 $faulty_root"
    pass=false
fi

# 3. Nothing was dropped on the floor. Actions in the blocks node 0 threw away
#    go back to its mempool and must end up confirmed on the chain it adopted —
#    the failure mode here is silent by construction: the transactions just
#    vanish and nothing logs an error.
missing_actions=0
for h in $(seq 1 "$CONFIRM_HEIGHT"); do
    sigs="$(curl -sf "http://127.0.0.1:$RPC_HONEST/blocks/$h" | jq -r '.actions[]?.signature // empty')"
    for sig in $sigs; do
        if ! curl -sf "http://127.0.0.1:$RPC_FAULTY/actions/$sig" >/dev/null; then
            # 404 is the loss condition: node 0 knows the action neither as
            # confirmed nor as pending, so it went in the bin with the block.
            echo "  FAIL: action $sig (honest height $h) is unknown to node 0 — neither confirmed nor pending"
            missing_actions=1
            pass=false
        fi
    done
done
if [ "$missing_actions" = 0 ]; then
    echo "  ok: no action from the honest chain went missing on node 0"
fi

# 4. Nobody rewrote history below its own watermark. That path refuses to touch
#    state and logs "HALT:" — its presence anywhere is a failure of the safety
#    rule, not of recovery.
halted=0
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    if grep -q "HALT:" "$ROOT/node-$i.log"; then
        echo "  FAIL: node $i halted below its watermark:"
        grep -m 1 "HALT:" "$ROOT/node-$i.log"
        halted=1
        pass=false
    fi
done
if [ "$halted" = 0 ]; then
    echo "  ok: no node reverted below its finalized watermark"
fi

if [ "$pass" = true ]; then
    echo
    echo "PASS — faulty proposer's dispute upheld and classed Attack (no slash until governance"
    echo "resolves it), no wrongful slash or self-incrimination, evidence written, kept block not disputed, and"
    echo "the diverged node's automatic rollback and reconvergence all held."
    echo "(Recursion guard not exercised by this scenario — see header comment.)"
    # Kept, not deleted. A passing run's logs are how a pass gets checked
    # against the run that came before it: deleting them made attempt 9 read
    # as "no detection" when it had in fact passed, and skewed the
    # stall-rate numbers a whole session was spent chasing.
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "logs and RPC captures kept in $ROOT"
    exit 0
else
    echo
    echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "FAIL — see $ROOT for logs and RPC captures."
    exit 1
fi
