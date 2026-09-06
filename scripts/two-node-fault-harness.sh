#!/usr/bin/env bash
# N-validator acceptance harness for the block-divergence fault loop (see
# Implementation_log's evidence/adjudication sections and docs/runbook.md).
#
# Boots NUM_VALIDATORS (default 4) local validators from a throwaway genesis:
# node 0 is built with `--features fault-injection` and armed to corrupt its
# own signed state_root at FAULT_HEIGHT; the rest are honest. The honest
# majority's independent re-execution must disagree with node 0's block,
# submit fault evidence, and drive node 0's stake to zero via on-chain
# adjudication — all without node 0 ever fabricating a counter-accusation.
# That's the recursion guard, the self-incrimination check, culprit
# resolution, and the slash landing, exercised against real processes
# instead of one test binary.
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
CHAIN_TIMEOUT=$(( (CONFIRM_HEIGHT + 3) * 2 + 30 ))

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

echo "building arxd with fault-injection..."
cargo build -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/debug/arxd"

echo "generating $NUM_VALIDATORS node identities and validator keys..."
VALIDATORS='{}'
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
done
PEER_0="$("$BIN" node-key --base-path "${DIRS[0]}")"

jq -n --argjson validators "$VALIDATORS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: {},
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

echo "checking node 0 did NOT fabricate a counter-accusation (self-incrimination guard)..."
evidence_0="$(curl -sf "http://127.0.0.1:${RPC_PORTS[0]}/evidence")"
if [ "$(echo "$evidence_0" | jq 'length')" -eq 0 ]; then
    echo "  ok: node 0's evidence dir is empty"
else
    echo "  FAIL: node 0 submitted evidence of its own: $evidence_0"
    pass=false
fi

if [ "$pass" = true ]; then
    echo
    echo "PASS — recursion guard, self-incrimination check, culprit resolution, and the slash landing all held."
    rm -rf "$ROOT"
    exit 0
else
    echo
    echo "FAIL — see $ROOT for logs and RPC captures."
    exit 1
fi
