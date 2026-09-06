#!/usr/bin/env bash
# N-validator acceptance harness for the block-divergence fault loop (see
# Implementation_log's evidence/adjudication sections and docs/runbook.md).
#
# Boots NUM_VALIDATORS (default 4) local validators from a throwaway genesis:
# node 0 is built with `--features fault-injection` and armed to corrupt its
# own signed state_root at FAULT_HEIGHT; the rest are honest. The honest
# majority's independent re-execution must disagree with node 0's block,
# submit fault evidence, and drive node 0's stake to zero via on-chain
# adjudication — all without node 0 ever landing a counter-slash against an
# honest validator. This exercises three separate guards against real
# processes instead of one test binary, and only two of them are actually
# checked below:
#   - Culprit resolution — checked: "honest nodes' stakes are untouched".
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
# NUM_VALIDATORS matters: quorum(n) = 2n/3 + 1, so at n=2 the faulty node's
# own vote is required for any quorum and the chain cannot advance past the
# disputed height at all — that's a quorum degeneracy, not evidence that
# reorg/rollback is required. Default here is 4 (quorum 3, faulty node
# outvoted) so a stall demonstrates an actual missing-machinery gap instead.
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
CONFIRM_HEIGHT=$((FAULT_HEIGHT + 6))
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
echo "harness scratch dir: $ROOT (kept on failure, removed on success)"

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
ACCOUNT_FUNDING=$((100 * 1000000))
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

jq -n --argjson validators "$VALIDATORS" --argjson accounts "$ACCOUNTS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

echo "starting node 0 (fault-injected at height $FAULT_HEIGHT) as ${ADDRS[0]} ..."
ARXD_INJECT_FAULT_AT_HEIGHT="$FAULT_HEIGHT" \
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

echo "checking node 0's (faulty) stake was slashed to zero..."
stake_status=$(curl -s -o "$ROOT/stake_0.json" -w '%{http_code}' "http://127.0.0.1:$RPC_HONEST/accounts/${ADDRS[0]}/stake")
if [ "$stake_status" = "404" ]; then
    echo "  ok: node 0's stake allocation was removed (fully slashed)"
elif [ "$stake_status" = "200" ] && [ "$(jq -r '.active_amount' "$ROOT/stake_0.json")" = "0" ]; then
    echo "  ok: node 0's active_amount is 0"
else
    echo "  FAIL: node 0's stake was not zeroed (http $stake_status): $(cat "$ROOT/stake_0.json")"
    pass=false
fi

# ponytail: this check is vacuous on its own — it passes trivially when no
# slash lands at all, which is exactly today's state under the evidence
# resubmission dedup gap (core/evidence/src/lib.rs:383). It only starts
# distinguishing "correctly not slashed" from "nothing happened" once node
# 0's stake check above actually reaches zero and `pass` is still riding on
# this one too — a lone "ok" here proves nothing by itself.
echo "checking honest nodes' stakes were left alone (culprit resolved to node 0 only)..."
for i in $(seq 1 $((NUM_VALIDATORS - 1))); do
    stake_status=$(curl -s -o "$ROOT/stake_$i.json" -w '%{http_code}' "http://127.0.0.1:$RPC_HONEST/accounts/${ADDRS[$i]}/stake")
    if [ "$stake_status" = "200" ] && [ "$(jq -r '.active_amount' "$ROOT/stake_$i.json")" != "0" ]; then
        echo "  ok: node $i's stake is untouched"
    else
        echo "  FAIL: node $i's stake was affected (http $stake_status): $(cat "$ROOT/stake_$i.json" 2>/dev/null)"
        pass=false
    fi
done

echo "checking an honest node submitted fault evidence..."
evidence_honest="$(curl -sf "http://127.0.0.1:$RPC_HONEST/evidence")"
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
    hits="$(echo "$block" | jq --arg addr "${ADDRS[0]}" '[.actions[]? | select(.sender == $addr) | select(.payload | has("SubmitExecutionFault"))]')"
    if [ "$(echo "$hits" | jq 'length')" -gt 0 ]; then
        echo "  FAIL: node 0 submitted a SubmitExecutionFault action at height $h: $hits"
        self_incrimination=1
        pass=false
    fi
done
if [ "$self_incrimination" = 0 ]; then
    echo "  ok: node 0 never submitted a fault action"
fi

if [ "$pass" = true ]; then
    echo
    echo "PASS — culprit resolution, self-incrimination, and the slash landing all held."
    echo "(Recursion guard not exercised by this scenario — see header comment.)"
    rm -rf "$ROOT"
    exit 0
else
    echo
    echo "FAIL — see $ROOT for logs and RPC captures."
    exit 1
fi
