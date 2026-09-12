#!/usr/bin/env bash
# Two-validator restart liveness test — the devnet stall of 2026-09-12.
#
# Sync serves blocks only up to the certified watermark and leaves the
# provisional tip to gossip, which delivers once. If validator B is down at
# the moment validator A proposes, B comes back holding the watermark, asks A
# for blocks above it, gets an empty page, and never sees the block it has to
# vote on; A cannot finalize without B. Two real processes, one SIGKILL and a
# restart from the same base path is the smallest thing that reproduces it.
#
# Adapted from two-node-liveness-harness.sh (same genesis/spawn machinery).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
WARMUP_HEIGHT="${WARMUP_HEIGHT:-6}"
RECOVER_BLOCKS="${RECOVER_BLOCKS:-5}"
RECOVER_TIMEOUT="${RECOVER_TIMEOUT:-90}"
BASE_RPC_PORT=18665
BASE_P2P_PORT=18721
STARTUP_TIMEOUT=30
CHAIN_TIMEOUT="${CHAIN_TIMEOUT:-120}"

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-restart-harness)"
echo "harness scratch dir: $ROOT (kept either way)"

declare -a DIRS RPC_PORTS P2P_PORTS PIDS ADDRS

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

if [ -n "${ARXD_BIN:-}" ]; then
    BIN="$ARXD_BIN"
else
    echo "building arxd (--release)..."
    cargo build --release -p arxd >"$ROOT/build.log" 2>&1 \
        || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
    BIN="$REPO_ROOT/target/release/arxd"
fi

echo "generating 2 node identities and validator keys..."
VALIDATORS='{}'
ACCOUNTS='{}'
for i in 0 1; do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
    ACCOUNTS="$(jq --arg addr "${ADDRS[$i]}" \
        '. + {($addr): {balance: 0, nonce: 0, identity_hash: null}}' <(echo "$ACCOUNTS"))"
done
PEER_0="$("$BIN" node-key --base-path "${DIRS[0]}")"

jq -n --argjson validators "$VALIDATORS" --argjson accounts "$ACCOUNTS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-restart-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

start_node() {
    local i=$1 log=$2 extra=()
    [ "$i" = 1 ] && extra=(--bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}/p2p/$PEER_0")
    RUST_LOG="${RUST_LOG:-info}" \
    "$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[$i]}" --validator \
        --port "${RPC_PORTS[$i]}" --p2p-port "${P2P_PORTS[$i]}" --rpc-bind 127.0.0.1 \
        ${extra[@]+"${extra[@]}"} >>"$log" 2>&1 &
    PIDS[$i]=$!
}

tip() { curl -sf "http://127.0.0.1:${RPC_PORTS[$1]}/status" | jq -r '.tip_height // 0'; }

wait_for_rpc() {
    local port=$1 deadline
    deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$port/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

echo "starting node 0 as ${ADDRS[0]}, node 1 as ${ADDRS[1]} ..."
start_node 0 "$ROOT/node-0.log"
start_node 1 "$ROOT/node-1.log"
for i in 0 1; do
    wait_for_rpc "${RPC_PORTS[$i]}" || { echo "node $i never came up, see $ROOT/node-$i.log" >&2; exit 1; }
done

echo "warming up to height $WARMUP_HEIGHT on both nodes..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(tip 0)" -ge "$WARMUP_HEIGHT" ] && [ "$(tip 1)" -ge "$WARMUP_HEIGHT" ] && break
    sleep 1
done
[ "$(tip 1)" -ge "$WARMUP_HEIGHT" ] || { echo "FAIL: warm-up never reached $WARMUP_HEIGHT" >&2; exit 1; }

# SIGKILL node 1 and wait for node 0 to propose a block on its own: that
# block is the provisional tip node 1 will have missed.
# Round-robin: kill node 1 right after it proposed, so the next height is
# node 0's slot and node 0 produces alone (the devnet shape: server2 proposed
# 61914 while server1 was down).
echo "waiting for a block proposed by node 1, then killing node 1 ..."
deadline=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$deadline" ]; do
    t="$(tip 0)"
    proposer="$(curl -sf "http://127.0.0.1:${RPC_PORTS[0]}/blocks/$t" | jq -r '.proposer // ""')"
    [ "$proposer" = "${ADDRS[1]}" ] && break
    sleep 0.2
done
kill -9 "${PIDS[1]}"; wait "${PIDS[1]}" 2>/dev/null || true
PIDS[1]=""
killed_at="$(tip 0)"
deadline=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(tip 0)" -gt "$killed_at" ] && break
    sleep 1
done
alone_tip="$(tip 0)"
if [ "$alone_tip" -le "$killed_at" ]; then
    echo "FAIL: node 0 never proposed alone after node 1 died (tip $alone_tip)" >&2; exit 1
fi
echo "node 0 proposed alone: tip $alone_tip (node 1 last saw <= $killed_at)"
sleep 10

echo "restarting node 1 from its own base path ..."
start_node 1 "$ROOT/node-1.log"
wait_for_rpc "${RPC_PORTS[1]}" || { echo "node 1 never came back, see $ROOT/node-1.log" >&2; exit 1; }

target=$((alone_tip + RECOVER_BLOCKS))
echo "waiting up to ${RECOVER_TIMEOUT}s for both nodes to pass height $target ..."
deadline=$(($(date +%s) + RECOVER_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    t0="$(tip 0)"; t1="$(tip 1)"
    [ "$t0" -ge "$target" ] && [ "$t1" -ge "$target" ] && break
    sleep 2
done
t0="$(tip 0)"; t1="$(tip 1)"
if [ "$t0" -ge "$target" ] && [ "$t1" -ge "$target" ]; then
    echo
    echo "PASS — chain resumed after a validator restart (node 0: $t0, node 1: $t1)."
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    exit 0
fi
echo
echo "FAIL — stalled after restart: node 0 at $t0, node 1 at $t1, wanted >= $target." >&2
echo "--- node 1 log (tail) ---" >&2; tail -n 12 "$ROOT/node-1.log" >&2
echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
exit 1
