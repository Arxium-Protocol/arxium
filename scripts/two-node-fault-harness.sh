#!/usr/bin/env bash
# Two-node acceptance harness for the block-divergence fault loop (see
# Implementation_log's evidence/adjudication sections and docs/runbook.md).
#
# Boots two local validators from a throwaway genesis: node A is honest,
# node B is built with `--features fault-injection` and armed to corrupt
# its own signed state_root at FAULT_HEIGHT. Node A's independent
# re-execution must then disagree with B's block, submit fault evidence,
# and drive B's stake to zero via on-chain adjudication — all without B
# ever fabricating a counter-accusation against A. That's the recursion
# guard, the self-incrimination check, culprit resolution, and the slash
# landing, exercised against two real processes instead of one test binary.
#
# What this does NOT prove: the loop working against an ordinary
# hundred-action block. This chain never carries other traffic, so
# artifact_json stays tiny regardless of the compression work already
# landed. It proves the logic, not production load.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAULT_HEIGHT="${FAULT_HEIGHT:-5}"
CONFIRM_HEIGHT=$((FAULT_HEIGHT + 6))
RPC_A=18545
RPC_B=18546
P2P_A=18601
P2P_B=18602
STARTUP_TIMEOUT=30
CHAIN_TIMEOUT=$(( (CONFIRM_HEIGHT + 3) * 2 + 30 ))

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-fault-harness)"
A="$ROOT/node-a"
B="$ROOT/node-b"
mkdir -p "$A" "$B"
echo "harness scratch dir: $ROOT (kept on failure, removed on success)"

PID_A=""
PID_B=""
cleanup() {
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    wait "$PID_A" "$PID_B" 2>/dev/null || true
}
trap cleanup EXIT

echo "building arxd with fault-injection..."
cargo build -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/debug/arxd"

echo "generating node identities and validator keys..."
PEER_A="$("$BIN" node-key --base-path "$A")"
ENTRY_A="$("$BIN" keys --base-path "$A" --json)"
ENTRY_B="$("$BIN" keys --base-path "$B" --json)"
ADDR_A="$(echo "$ENTRY_A" | jq -r 'keys[0]')"
ADDR_B="$(echo "$ENTRY_B" | jq -r 'keys[0]')"
VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$ENTRY_A") <(echo "$ENTRY_B"))"

jq -n --argjson validators "$VALIDATORS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: {},
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

echo "starting node A (honest) as $ADDR_A ..."
"$BIN" --chain "$ROOT/genesis.json" --base-path "$A" --validator \
    --port "$RPC_A" --p2p-port "$P2P_A" --rpc-bind 127.0.0.1 \
    >"$ROOT/node-a.log" 2>&1 &
PID_A=$!

echo "starting node B (fault-injected at height $FAULT_HEIGHT) as $ADDR_B ..."
ARXD_INJECT_FAULT_AT_HEIGHT="$FAULT_HEIGHT" \
"$BIN" --chain "$ROOT/genesis.json" --base-path "$B" --validator \
    --port "$RPC_B" --p2p-port "$P2P_B" --rpc-bind 127.0.0.1 \
    --bootnodes "/ip4/127.0.0.1/tcp/$P2P_A/p2p/$PEER_A" \
    >"$ROOT/node-b.log" 2>&1 &
PID_B=$!

wait_for_rpc() {
    local port=$1 deadline
    deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$port/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
wait_for_rpc "$RPC_A" || { echo "node A never came up, see $ROOT/node-a.log" >&2; exit 1; }
wait_for_rpc "$RPC_B" || { echo "node B never came up, see $ROOT/node-b.log" >&2; exit 1; }

echo "waiting for chain to pass height $CONFIRM_HEIGHT (timeout ${CHAIN_TIMEOUT}s)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
tip=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    tip="$(curl -sf "http://127.0.0.1:$RPC_A/status" | jq -r '.tip_height // 0')"
    [ "$tip" -ge "$CONFIRM_HEIGHT" ] && break
    sleep 2
done
if [ "$tip" -lt "$CONFIRM_HEIGHT" ]; then
    echo "FAIL: node A only reached height $tip, expected >= $CONFIRM_HEIGHT" >&2
    echo "--- node A log (tail) ---" >&2; tail -n 40 "$ROOT/node-a.log" >&2
    echo "--- node B log (tail) ---" >&2; tail -n 40 "$ROOT/node-b.log" >&2
    exit 1
fi
echo "chain reached height $tip"

pass=true

echo "checking B's stake was slashed to zero..."
stake_status=$(curl -s -o "$ROOT/stake_b.json" -w '%{http_code}' "http://127.0.0.1:$RPC_A/accounts/$ADDR_B/stake")
if [ "$stake_status" = "404" ]; then
    echo "  ok: B's stake allocation was removed (fully slashed)"
elif [ "$stake_status" = "200" ] && [ "$(jq -r '.active_amount' "$ROOT/stake_b.json")" = "0" ]; then
    echo "  ok: B's active_amount is 0"
else
    echo "  FAIL: B's stake was not zeroed (http $stake_status): $(cat "$ROOT/stake_b.json")"
    pass=false
fi

echo "checking A's stake was left alone (culprit resolved to B, not A)..."
stake_a_status=$(curl -s -o "$ROOT/stake_a.json" -w '%{http_code}' "http://127.0.0.1:$RPC_A/accounts/$ADDR_A/stake")
if [ "$stake_a_status" = "200" ] && [ "$(jq -r '.active_amount' "$ROOT/stake_a.json")" != "0" ]; then
    echo "  ok: A's stake is untouched"
else
    echo "  FAIL: A's stake was affected (http $stake_a_status): $(cat "$ROOT/stake_a.json" 2>/dev/null)"
    pass=false
fi

echo "checking A submitted fault evidence..."
evidence_a="$(curl -sf "http://127.0.0.1:$RPC_A/evidence")"
if [ "$(echo "$evidence_a" | jq 'length')" -gt 0 ]; then
    echo "  ok: A's evidence dir has $(echo "$evidence_a" | jq 'length') artifact(s)"
else
    echo "  FAIL: A never wrote a fault-evidence artifact"
    pass=false
fi

echo "checking B did NOT fabricate a counter-accusation (self-incrimination guard)..."
evidence_b="$(curl -sf "http://127.0.0.1:$RPC_B/evidence")"
if [ "$(echo "$evidence_b" | jq 'length')" -eq 0 ]; then
    echo "  ok: B's evidence dir is empty"
else
    echo "  FAIL: B submitted evidence of its own: $evidence_b"
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
