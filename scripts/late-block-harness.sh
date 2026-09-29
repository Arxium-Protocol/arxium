#!/usr/bin/env bash
# Regression harness for Trello D-25: a block that reaches a validator after
# it already voted that round timed out leaves a permanent certificate hole.
#
# Two validators, the relaunched devnet's shape: quorum is 6,667 of 10,000
# and each holds 5,000, so every height needs both precommits. The run cuts
# node 1 off (a restart with ARXD_BLOCK_PEERS) while the tips are level at T
# and T+1 is node 0's round-0 slot — a restarted node with no peers sits in
# the boot sync gate for minutes, so it must not be the one expected to
# produce. Node 0 builds and precommits T+1 alone; node 1 signs a
# round-timeout vote for (T+1, 0) once ROUND_TIMEOUT (8s) passes. Neither
# side has a quorum. On heal the late side
# receives the block but S2 (docs/consensus-safety.md §2) forbids it to
# precommit a round it declared timed out, so T+1 never certifies — while
# T+2 onward do, since both vote those normally.
#
# Pass means final_watermark followed finalized_height past T+1. Until the
# round-change redesign lands (docs/consensus-round-change.md) this harness
# is EXPECTED TO FAIL: it is the reproduction, kept so the fix has a check.
#
# Exit codes: 0 pass, 1 fail, 3 INCONCLUSIVE (the split never happened —
# same convention and reasoning as partition-heal-harness.sh).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WARMUP_HEIGHT="${WARMUP_HEIGHT:-6}"
# Distinct from the fault (18545) and partition (18645) harnesses' ports.
BASE_RPC_PORT=18745
BASE_P2P_PORT=18801
STARTUP_TIMEOUT=30
CHAIN_TIMEOUT=180
# arxd/finality's ROUND_TIMEOUT is 8s; the isolated side must have signed
# its timeout vote before the heal, or it would simply precommit the block.
SPLIT_HOLD_SECS=20

for tool in jq curl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(mktemp -d -t arxium-late-block-harness)"
echo "harness scratch dir: $ROOT (kept either way)"

declare -a DIRS RPC_PORTS P2P_PORTS PIDS ADDRS PEERS
cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# --release and fault-injection: see partition-heal-harness.sh.
echo "building arxd with fault-injection (--release)..."
cargo build --release -p arxd --features fault-injection >"$ROOT/build.log" 2>&1 \
    || { echo "build failed, see $ROOT/build.log" >&2; exit 1; }
BIN="$REPO_ROOT/target/release/arxd"

VALIDATORS='{}'
for i in 0 1; do
    DIRS[$i]="$ROOT/node-$i"
    mkdir -p "${DIRS[$i]}"
    RPC_PORTS[$i]=$((BASE_RPC_PORT + i))
    P2P_PORTS[$i]=$((BASE_P2P_PORT + i))
    entry="$("$BIN" keys --base-path "${DIRS[$i]}" --json)"
    ADDRS[$i]="$(echo "$entry" | jq -r 'keys[0]')"
    PEERS[$i]="$("$BIN" node-key --base-path "${DIRS[$i]}")"
    VALIDATORS="$(jq -s '.[0] * .[1]' <(echo "$VALIDATORS") <(echo "$entry"))"
done

# Round-0 proposer of h is sorted(addresses)[h % 2] (eligible_proposer).
NODE0_SLOT=0
[ "$(printf '%s\n' "${ADDRS[@]}" | LC_ALL=C sort | head -n 1)" = "${ADDRS[0]}" ] || NODE0_SLOT=1

# The one chain name arxd accepts ARXD_BLOCK_PEERS on.
jq -n --argjson validators "$VALIDATORS" '{
    genesis_format: "plain",
    height: 0,
    chain_name: "arxium-fault-injection-harness",
    accounts: {},
    validators: $validators,
    boot_nodes: []
}' > "$ROOT/genesis.json"

start_node() {
    # $1 = index, $2... = extra env assignments
    local i=$1; shift
    local bootnode=()
    [ "$i" != 0 ] && bootnode=(--bootnodes "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}/p2p/${PEERS[0]}")
    env RUST_LOG="${RUST_LOG:-info}" "$@" "$BIN" --chain "$ROOT/genesis.json" --base-path "${DIRS[$i]}" --validator \
        --port "${RPC_PORTS[$i]}" --p2p-port "${P2P_PORTS[$i]}" --rpc-bind 127.0.0.1 \
        ${bootnode[@]+"${bootnode[@]}"} \
        >>"$ROOT/node-$i.log" 2>&1 &
    PIDS[$i]=$!
}
wait_for_rpc() {
    local deadline=$(($(date +%s) + STARTUP_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        curl -sf "http://127.0.0.1:$1/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
status_field() { { curl -sf "http://127.0.0.1:$1/status" || echo '{}'; } | jq -r ".$2 // 0"; }
inconclusive() {
    echo "INCONCLUSIVE $(date -u +%Y-%m-%dT%H:%M:%SZ): $*" > "$ROOT/result"
    echo "INCONCLUSIVE — $*. Nothing was tested. Logs in $ROOT." >&2
    exit 3
}

for i in 0 1; do start_node "$i"; done
for i in 0 1; do
    wait_for_rpc "${RPC_PORTS[$i]}" || { echo "node $i never came up, see $ROOT/node-$i.log" >&2; exit 1; }
done

echo "waiting for both nodes to finalize past height $WARMUP_HEIGHT..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
steady=false
while [ "$(date +%s)" -lt "$deadline" ]; do
    t0="$(status_field "${RPC_PORTS[0]}" tip_height)"
    t1="$(status_field "${RPC_PORTS[1]}" tip_height)"
    w0="$(status_field "${RPC_PORTS[0]}" final_watermark)"
    if [ "$t0" = "$t1" ] && [ "$w0" -ge "$WARMUP_HEIGHT" ] && [ "$w0" = "$t0" ] \
        && [ $(( (t0 + 1) % 2 )) = "$NODE0_SLOT" ]; then
        steady=true; break
    fi
    sleep 0.2
done
[ "$steady" = true ] || inconclusive "never reached a level, fully finalized tip (tips $t0/$t1, watermark $w0)"
T=$t0
HOLE=$((T + 1))
echo "  level and finalized at $T; cutting node 1 off"

kill "${PIDS[1]}" 2>/dev/null || true
wait "${PIDS[1]}" 2>/dev/null || true
start_node 1 "ARXD_BLOCK_PEERS=${PEERS[0]}"
wait_for_rpc "${RPC_PORTS[1]}" || { echo "node 1 never came back up, see $ROOT/node-1.log" >&2; exit 1; }

echo "holding the split ${SPLIT_HOLD_SECS}s so the side without $HOLE times it out..."
sleep "$SPLIT_HOLD_SECS"
t0="$(status_field "${RPC_PORTS[0]}" tip_height)"
t1="$(status_field "${RPC_PORTS[1]}" tip_height)"
w0="$(status_field "${RPC_PORTS[0]}" final_watermark)"
# Node 0 built HOLE alone and node 1 never saw it.
if [ "$t0" = "$HOLE" ] && [ "$t1" = "$T" ]; then
    echo "  ok: node 0 built $HOLE alone, node 1 still at $T"
else
    inconclusive "no clean split: tips $t0/$t1, expected node 0 at $HOLE and node 1 at $T"
fi
[ "$w0" -lt "$HOLE" ] || inconclusive "height $HOLE finalized during the split (watermark $w0) — node 1 was never cut off"

echo "healing (restarting node 1 without the block list)..."
kill "${PIDS[1]}" 2>/dev/null || true
wait "${PIDS[1]}" 2>/dev/null || true
start_node 1
wait_for_rpc "${RPC_PORTS[1]}" || { echo "node 1 never came back up, see $ROOT/node-1.log" >&2; exit 1; }

pass=true
BAR=$((HOLE + 3))
echo "waiting for finality to resume past $BAR..."
deadline=$(($(date +%s) + CHAIN_TIMEOUT))
f0=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    f0="$(status_field "${RPC_PORTS[0]}" finalized_height)"
    [ "$f0" -ge "$BAR" ] && break
    sleep 2
done
if [ "$f0" -ge "$BAR" ]; then
    echo "  ok: finalized_height reached $f0"
else
    echo "  FAIL: finality never resumed after the heal (finalized_height $f0)"
    pass=false
fi

# The actual D-25 property: the contiguous watermark must follow. Some
# seconds of slack, since certificates can land out of order.
echo "checking final_watermark followed finalized_height past $HOLE..."
deadline=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$deadline" ]; do
    w0="$(status_field "${RPC_PORTS[0]}" final_watermark)"
    w1="$(status_field "${RPC_PORTS[1]}" final_watermark)"
    [ "$w0" -gt "$HOLE" ] && [ "$w1" -gt "$HOLE" ] && break
    sleep 2
done
for i in 0 1; do
    f="$(status_field "${RPC_PORTS[$i]}" finalized_height)"
    w="$(status_field "${RPC_PORTS[$i]}" final_watermark)"
    if [ "$w" -gt "$HOLE" ]; then
        echo "  ok: node $i watermark $w (finalized_height $f)"
    else
        echo "  FAIL: node $i watermark stuck at $w while finalized_height is $f — certificate hole at $HOLE (D-25)"
        pass=false
    fi
done
grep -h "already voted that round timed out" "$ROOT"/node-*.log | head -n 1 | sed 's/^/  note: /' || true

if [ "$pass" = true ]; then
    echo "PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
    echo "PASS — a late block after a timeout vote did not leave a certificate hole."
    exit 0
fi
echo "FAIL $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/result"
echo "FAIL — see logs in $ROOT."
exit 1
