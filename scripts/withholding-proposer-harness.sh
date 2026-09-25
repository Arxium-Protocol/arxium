#!/usr/bin/env bash
# Withholding-proposer acceptance harness for B1c (docs/consensus-safety.md §3).
#
# Four validators, quorum 3. The round-0 proposer of TARGET_H, P0, is
# Byzantine: it hands its block A to exactly one honest node, N1, withholds
# it from N2 and N3, and never precommits at that height. Before B1c this
# stalled the height forever (A = P0+N1, B = N2+N3). After it:
#
#   - N2, N3 and P0 time out round 0 (P0 may: it never voted), certifying it;
#   - N2, the round-1 proposer, proposes B@1 with that certificate;
#   - N1 unwinds A — on tallying the certificate itself (arxd/finality
#     unwind_dead_tip) or on seeing B's (xc_executor supersede_dead_tip),
#     whichever lands first — and votes B@1;
#   - B finalizes. P0 never votes at TARGET_H, so the quorum is N1+N2+N3.
#
# Asserted: final_watermark passes TARGET_H on all three honest nodes, all
# three hold the same round-1 block there, arxium_dead_tips_unwound_total is
# 1 on N1, A is in nobody's chain, and no PrecommitEquivocation is reported
# anywhere — N1's A@0 then B@1 is two rounds, not a double vote.
#
# How the fault is built (needs --features fault-injection, and
# arxd/node refuses it off the "arxium-fault-injection-harness" chain):
#
#   P0  ARXD_WITHHOLD_BLOCK_AT_HEIGHT=TARGET_H, ARXD_WITHHOLD_EXCEPT_PEERS=N1.
#       Its block at TARGET_H is never gossiped and is served over sync to N1
#       only; everyone else is told its tip is TARGET_H - 1. arxd/finality
#       drops the height entirely, so it neither votes nor counts it as
#       progress — which is what lets it co-sign round 0's timeout.
#   N1  ARXD_BLOCK_PEERS=N2,N3. An honest N1 would otherwise hand A straight
#       to N2/N3 over sync (it serves its provisional tip to peers at the
#       watermark), and they would vote it and finalize A — the benign
#       outcome, not the one under test. Cut off from them, N1 hears the rest
#       of the network through P0, which relays gossip honestly. Also a wide
#       ARXD_ROUND_TIMEOUT_SECS, so N1 cannot time out round 0 (and so,
#       by S2, refuse to vote A) before its next Status tick pulls A.
#   P0, N2, N3  ARXD_ROUND_TIMEOUT_SECS=ROUND_TIMEOUT_SECS (default 20), so
#       round 0 lasts several STATUS_INTERVALs (5s) — N1 has to pull A before
#       the certificate lands and P0 unwinds it.
#
# Roles are assigned by slot, since xc_primitives::eligible_proposer is
# sorted(addresses)[(height + round) % 4]: P0 holds TARGET_H's slot, N2 the
# next (round 1's proposer), N1 and N3 the other two. N1 must not be round
# 1's proposer — it would be proposing on top of the block it is meant to
# abandon.
#
# ponytail: the 2|2 split-and-heal case the card mentions is not here. With
# quorum 3 neither half finalizes, so it only proves "no quorum, no
# progress" plus the same unwind partition-heal-harness.sh already covers;
# add it if a 2|2 run ever needs to show something the 3|1 one does not.
#
# Exit codes: 0 pass, 1 fail, 3 INCONCLUSIVE (the scenario never set up —
# not a pass; see partition-heal-harness.sh for why this is separate).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

N=4
TARGET_H="${TARGET_H:-12}"
ROUND_TIMEOUT_SECS="${ROUND_TIMEOUT_SECS:-20}"
N1_ROUND_TIMEOUT_SECS="${N1_ROUND_TIMEOUT_SECS:-600}"
# Own ports, so this can run next to the other harnesses.
BASE_RPC_PORT=18745
BASE_P2P_PORT=18801
STARTUP_TIMEOUT=30
CHAIN_TIMEOUT=300

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-withhold-harness)"
echo "harness scratch dir: $ROOT (kept either way)"

declare -a DIRS RPC_PORTS P2P_PORTS PIDS ADDRS PEERS

cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# --release: see two-node-fault-harness.sh (a libp2p debug_assert under churn).
echo "building arxd with fault-injection (--release)..."
cargo build --release -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/release/arxd"

echo "generating $N node identities and validator keys..."
VALIDATORS='{}'
ACCOUNTS='{}'
for i in $(seq 0 $((N - 1))); do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    PEERS[$i]="$("$BIN" node-key --base-path "${DIRS[$i]}")"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
    ACCOUNTS="$(jq --arg addr "${ADDRS[$i]}" '. + {($addr): {balance: 100000000, nonce: 0, identity_hash: null}}' <(echo "$ACCOUNTS"))"
done

# Node index holding sorted-address slot $1.
SORTED_ADDRS=($(printf '%s\n' "${ADDRS[@]}" | LC_ALL=C sort))
node_at_slot() {
    local i
    for i in $(seq 0 $((N - 1))); do
        [ "${ADDRS[$i]}" = "${SORTED_ADDRS[$1]}" ] && { echo "$i"; return; }
    done
}
P0=$(node_at_slot $((TARGET_H % N)))
N2=$(node_at_slot $(((TARGET_H + 1) % N)))
N1=$(node_at_slot $(((TARGET_H + 2) % N)))
N3=$(node_at_slot $(((TARGET_H + 3) % N)))
HONEST=("$N1" "$N2" "$N3")
echo "roles at height $TARGET_H: P0=node-$P0 (withholds)  N1=node-$N1 (gets A)  N2=node-$N2 (round-1 proposer)  N3=node-$N3"

jq -n --argjson validators "$VALIDATORS" --argjson accounts "$ACCOUNTS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: [],
    params: {}
}' > "$ROOT/genesis.json"

start_node() {
    # $1 = index, $2... = extra env assignments. Star on P0: it is the one
    # node everybody, N1 included, is allowed to reach. RUST_LOG is pinned
    # because every grep below reads these logs (see partition harness).
    local i=$1; shift
    local bootnode=()
    [ "$i" != "$P0" ] && bootnode=(--bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[$P0]}/p2p/${PEERS[$P0]}")
    env RUST_LOG="${RUST_LOG:-info}" "$@" "$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[$i]}" --validator \
        --port "${RPC_PORTS[$i]}" --p2p-port "${P2P_PORTS[$i]}" --rpc-bind 127.0.0.1 \
        ${bootnode[@]+"${bootnode[@]}"} \
        >>"$ROOT/node-$i.log" 2>&1 &
    PIDS[$i]=$!
}

start_node "$P0" "ARXD_ROUND_TIMEOUT_SECS=$ROUND_TIMEOUT_SECS" \
    "ARXD_WITHHOLD_BLOCK_AT_HEIGHT=$TARGET_H" "ARXD_WITHHOLD_EXCEPT_PEERS=${PEERS[$N1]}"
start_node "$N1" "ARXD_ROUND_TIMEOUT_SECS=$N1_ROUND_TIMEOUT_SECS" \
    "ARXD_BLOCK_PEERS=${PEERS[$N2]},${PEERS[$N3]}"
start_node "$N2" "ARXD_ROUND_TIMEOUT_SECS=$ROUND_TIMEOUT_SECS"
start_node "$N3" "ARXD_ROUND_TIMEOUT_SECS=$ROUND_TIMEOUT_SECS"

wait_for_rpc() {
    local port=$1 deadline
    deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$port/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
for i in $(seq 0 $((N - 1))); do
    wait_for_rpc "${RPC_PORTS[$i]}" || { echo "node $i never came up, see $ROOT/node-$i.log" >&2; exit 1; }
done

rpc() { curl -sf "http://127.0.0.1:${RPC_PORTS[$1]}$2" || true; }
status_field() { rpc "$1" /status | jq -r ".$2 // 0"; }
has_block() { [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${RPC_PORTS[$1]}/blocks/by-hash/$2")" = 200 ]; }
metric() { rpc "$1" /metrics | awk -v m="$2" '$1 == m { print $2; found=1 } END { if (!found) print 0 }'; }

inconclusive() {
    echo
    echo "$*" >&2
    echo "INCONCLUSIVE $(date -u +%Y-%m-%dT%H:%M:%SZ): $*" > "$ROOT/result"
    echo "INCONCLUSIVE — the withholding scenario never set up, so nothing was tested." >&2
    echo "This is not a pass. Logs in $ROOT." >&2
    exit 3
}

# --- Setup: P0 builds A, only N1 gets it ------------------------------------
#
# Polled fast: P0 unwinds A as soon as round 0 certifies, so both "P0 holds
# A" and "N1 holds A" are windows, not end states.
echo "waiting for P0 to produce and withhold its block at $TARGET_H..."
A_HASH=""
n1_had_a=false
leaked=""
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -z "$A_HASH" ]; then
        s="$(rpc "$P0" /status)"
        if [ "$(echo "$s" | jq -r '.tip_height // 0')" = "$TARGET_H" ] \
            && grep -q "withholding block $TARGET_H " "$ROOT/node-$P0.log"; then
            A_HASH="$(echo "$s" | jq -r '.tip_hash')"
            echo "  P0 holds A = $A_HASH"
        fi
    fi
    if [ -n "$A_HASH" ]; then
        has_block "$N1" "$A_HASH" && n1_had_a=true
        for i in "$N2" "$N3"; do has_block "$i" "$A_HASH" && leaked="$leaked node-$i"; done
    fi
    [ "$n1_had_a" = true ] && break
    [ "$(status_field "$N2" tip_height)" -gt "$TARGET_H" ] && break
    sleep 0.2
done
[ -n "$A_HASH" ] || inconclusive "P0 never produced its withheld block at $TARGET_H (see $ROOT/node-$P0.log)"
[ "$n1_had_a" = true ] \
    || inconclusive "N1 never held A — the round-0 certificate beat N1's sync pull. Raise ROUND_TIMEOUT_SECS (currently $ROUND_TIMEOUT_SECS)."
echo "  ok: N1 holds A at $TARGET_H"

# S2: an N1 that timed out round 0 before pulling A would decline to vote
# it, and the run would never show a legitimate A@0-then-B@1 pair.
if grep -q "not precommitting block $TARGET_H at round 0" "$ROOT/node-$N1.log"; then
    inconclusive "N1 timed out round 0 before it saw A, so it never voted A@0 — N1_ROUND_TIMEOUT_SECS too short?"
fi

# --- Resolution --------------------------------------------------------------
echo "waiting for all honest nodes to finalize past $TARGET_H..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    for i in "$N2" "$N3"; do has_block "$i" "$A_HASH" && leaked="$leaked node-$i"; done
    done_all=true
    for i in "${HONEST[@]}"; do
        [ "$(status_field "$i" final_watermark)" -gt "$TARGET_H" ] || done_all=false
    done
    [ "$done_all" = true ] && break
    sleep 1
done

pass=true
fail() { echo "  FAIL: $*"; pass=false; }

echo "checking P0 withheld and never voted at $TARGET_H..."
grep -q "not voting at withheld height $TARGET_H " "$ROOT/node-$P0.log" \
    && echo "  ok: P0 dropped its own block from finality" \
    || fail "P0 never logged skipping its vote at $TARGET_H"
[ -z "$leaked" ] && echo "  ok: A never reached N2/N3" || fail "A reached$leaked — withholding leaked"

echo "checking final_watermark passed $TARGET_H on N1, N2, N3..."
for i in "${HONEST[@]}"; do
    w="$(status_field "$i" final_watermark)"
    [ "$w" -gt "$TARGET_H" ] && echo "  ok: node-$i watermark $w" || fail "node-$i watermark $w, never passed $TARGET_H"
done

echo "checking the honest nodes agree on a round-1 block at $TARGET_H..."
B_HASH="$(rpc "$N2" "/blocks/$((TARGET_H + 1))" | jq -r '.parent_hash // ""')"
B_ROUND="$(rpc "$N2" "/blocks/$TARGET_H" | jq -r '.round // ""')"
[ -n "$B_HASH" ] && [ "$B_HASH" != "$A_HASH" ] || fail "N2's block at $TARGET_H is '$B_HASH' (A is $A_HASH)"
[ "$B_ROUND" = 1 ] && echo "  ok: B = $B_HASH at round 1" || fail "block at $TARGET_H is round '$B_ROUND', expected 1"
for i in "$N1" "$N3"; do
    h="$(rpc "$i" "/blocks/$((TARGET_H + 1))" | jq -r '.parent_hash // ""')"
    [ "$h" = "$B_HASH" ] && echo "  ok: node-$i holds B" || fail "node-$i holds '$h' at $TARGET_H"
done
# P0 never voted at TARGET_H, so a quorum of 3 there is exactly N1+N2+N3.

echo "checking N1 unwound A exactly once..."
unwound="$(metric "$N1" arxium_dead_tips_unwound_total)"
[ "$unwound" = 1 ] && echo "  ok: arxium_dead_tips_unwound_total = 1 on N1" || fail "arxium_dead_tips_unwound_total = $unwound on N1"
grep -m1 -oE "(round 0 at height $TARGET_H timed out|block $TARGET_H at round 1 supersedes).*" "$ROOT/node-$N1.log" | sed 's/^/  via: /' || true
has_block "$N1" "$A_HASH" && fail "N1 still has A in its chain" || echo "  ok: A is gone from N1"

echo "checking no precommit equivocation was reported..."
equivocated=false
for i in $(seq 0 $((N - 1))); do
    if grep -q "precommitted twice" "$ROOT/node-$i.log" \
        || [ "$(metric "$i" arxium_precommit_equivocations_detected_total)" != 0 ]; then
        fail "node-$i reported an equivocation: $(grep -m1 'precommitted twice' "$ROOT/node-$i.log" || true)"
        equivocated=true
    fi
done
[ "$equivocated" = false ] && echo "  ok: none"

echo "checking no node halted..."
for i in $(seq 0 $((N - 1))); do
    grep -q "HALT:" "$ROOT/node-$i.log" && fail "node-$i halted: $(grep -m1 'HALT:' "$ROOT/node-$i.log")"
done

echo
if [ "$pass" = true ]; then
    echo "PASS — P0 withheld A@0 at $TARGET_H from all but N1 and never voted; N1 voted"
    echo "A, round 0 certified without it, N1 unwound A and B@1 finalized with N1+N2+N3."
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "logs kept in $ROOT"
    exit 0
fi
echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
echo "FAIL — see logs in $ROOT."
exit 1
