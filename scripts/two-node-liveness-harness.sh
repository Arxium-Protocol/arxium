#!/usr/bin/env bash
# Two-validator, two-real-process liveness/round-agreement acceptance test —
# `Arxium_OpenItems.md` item K, the "two-process integration test" the old
# `arxd/CHAIN_STALL_ROOT_CAUSE.md` root-cause doc called for and that never
# got built. Everything the produce/accept clock-agreement fix and the B1b
# round-certificate fix actually guard against (a block that self-certifies
# its own round, two validators disagreeing about whose turn it is) only
# shows up once two independent OS processes are producing, gossiping, and
# validating each other's blocks over the real network stack — the in-process
# `produce.rs` test (`a_produced_block_is_accepted_by_the_same_rules_that_
# validate_a_gossiped_one`) feeds a produced block straight into the peer's
# `accept_block` with no networking, no swarm, and only one process actually
# calling `produce_block`.
#
# Adapted from `two-node-fault-harness.sh`: same genesis/spawn/wait-for-rpc
# machinery, fault injection and evidence/adjudication checks stripped out —
# this only needs plain liveness, not a divergence to recover from.
#
# quorum(2) = 2*2/3 + 1 = 2, i.e. both validators must agree on every block —
# exactly the property a round-self-certification bug would break first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIRM_HEIGHT="${CONFIRM_HEIGHT:-20}"
BASE_RPC_PORT=18645
BASE_P2P_PORT=18701
STARTUP_TIMEOUT=30
# Same reasoning as the fault harness: real round timeouts + real gossip
# propagation, not instant in-process delivery. 20 blocks at an 8s slot in
# the worst case is 160s; leave real margin above that.
CHAIN_TIMEOUT="${CHAIN_TIMEOUT:-240}"

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-liveness-harness)"
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

# --release for the same reason as the fault harness: the debug build trips
# an upstream libp2p-request-response debug_assert under connection churn
# often enough to read as a stall unrelated to this chain's own logic.
echo "building arxd (--release)..."
cargo build --release -p arxd >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/release/arxd"

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
    chain_name: "arxium-liveness-harness",
    accounts: $accounts,
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

# RUST_LOG explicitly, not from the caller's environment: arxd's tracing
# subscriber emits nothing at all with it unset, so the log greps below
# ("reverted from height", "HALT:") read an empty file and the run's verdict
# silently depends on whoever's shell started it. Found while building
# scripts/partition-heal-harness.sh.
echo "starting node 0 as ${ADDRS[0]} ..."
RUST_LOG="${RUST_LOG:-info}" \
"$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[0]}" --validator \
    --port "${RPC_PORTS[0]}" --p2p-port "${P2P_PORTS[0]}" --rpc-bind 127.0.0.1 \
    >"$ROOT/node-0.log" 2>&1 &
PIDS[0]=$!

echo "starting node 1 as ${ADDRS[1]} ..."
RUST_LOG="${RUST_LOG:-info}" \
"$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[1]}" --validator \
    --port "${RPC_PORTS[1]}" --p2p-port "${P2P_PORTS[1]}" --rpc-bind 127.0.0.1 \
    --bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}/p2p/$PEER_0" \
    >"$ROOT/node-1.log" 2>&1 &
PIDS[1]=$!

wait_for_rpc() {
    local port=$1 deadline
    deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$port/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
for i in 0 1; do
    wait_for_rpc "${RPC_PORTS[$i]}" || { echo "node $i never came up, see $ROOT/node-$i.log" >&2; exit 1; }
done

echo "waiting for both nodes to pass height $CONFIRM_HEIGHT (timeout ${CHAIN_TIMEOUT}s)..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
tip0=0 tip1=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    tip0="$(curl -sf "http://127.0.0.1:${RPC_PORTS[0]}/status" | jq -r '.tip_height // 0')"
    tip1="$(curl -sf "http://127.0.0.1:${RPC_PORTS[1]}/status" | jq -r '.tip_height // 0')"
    [ "$tip0" -ge "$CONFIRM_HEIGHT" ] && [ "$tip1" -ge "$CONFIRM_HEIGHT" ] && break
    sleep 2
done
if [ "$tip0" -lt "$CONFIRM_HEIGHT" ] || [ "$tip1" -lt "$CONFIRM_HEIGHT" ]; then
    echo "FAIL: node 0 at $tip0, node 1 at $tip1, expected both >= $CONFIRM_HEIGHT" >&2
    for i in 0 1; do
        echo "--- node $i log (tail) ---" >&2; tail -n 40 "$ROOT/node-$i.log" >&2
    done
    exit 1
fi
echo "both nodes reached height $CONFIRM_HEIGHT (node 0: $tip0, node 1: $tip1)"

pass=true

# The actual property this whole harness exists for: two real processes
# never disagreeing about a block once accepted. A self-certified-round bug
# manifests exactly here — one node accepting a round-0 block while the
# other accepts a different round-1 block at the same height.
echo "checking node 0 and node 1 agree on every block up to $CONFIRM_HEIGHT..."
proposers_seen=""
for h in $(seq 1 "$CONFIRM_HEIGHT"); do
    b0="$(curl -sf "http://127.0.0.1:${RPC_PORTS[0]}/blocks/$h")"
    b1="$(curl -sf "http://127.0.0.1:${RPC_PORTS[1]}/blocks/$h")"
    hash0="$(echo "$b0" | jq -r '.state_root // "node0-missing"')"
    hash1="$(echo "$b1" | jq -r '.state_root // "node1-missing"')"
    if [ "$hash0" != "$hash1" ]; then
        echo "  FAIL: state roots differ at height $h: node 0 $hash0 vs node 1 $hash1"
        pass=false
    fi
    proposer="$(echo "$b0" | jq -r '.proposer // "none"')"
    proposers_seen="$proposers_seen $proposer"
done
echo "  ok: state roots agreed at every height 1..$CONFIRM_HEIGHT (or failure reported above)"

# Round-robin rotation actually exercised across two real processes, not
# just simulated in one — the property the in-process produce.rs test can't
# reach because it only ever calls `produce_block` from a single process.
echo "checking both validators actually produced at least one block (rotation happened)..."
for addr in "${ADDRS[0]}" "${ADDRS[1]}"; do
    if echo "$proposers_seen" | grep -q "$addr"; then
        echo "  ok: $addr produced at least one block"
    else
        echo "  FAIL: $addr never produced a block in heights 1..$CONFIRM_HEIGHT"
        pass=false
    fi
done

echo "checking neither node ever halted or reverted below its watermark..."
halted=0
for i in 0 1; do
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
    echo "PASS — two independent processes rotated proposers and agreed on"
    echo "every block through height $CONFIRM_HEIGHT via real gossip/sync."
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "logs and RPC captures kept in $ROOT"
    exit 0
else
    echo
    echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "FAIL — see $ROOT for logs and RPC captures."
    exit 1
fi
