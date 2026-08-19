# Arxium Chain Production Stall: Root-Cause Analysis

## Executive summary

The `arxd` process remains healthy from systemd's point of view but stops
producing blocks because the proposer-selection algorithm can permanently
assign the next block to an offline validator.

The deployed devnet contains two validators, Alice and Bob, while only Bob's
validator node is running. Proposer eligibility starts with the validator
selected for the block height and advances after each four-second slot. The
current implementation stops advancing after it reaches the last fallback;
it never starts another round through the validator set. If Bob misses his
only eligibility window, the height remains assigned to offline Alice
forever. Bob continues checking every two seconds, silently decides that it
is not eligible, and skips production. Consequently, the process, RPC server,
and P2P subsystem remain active even though chain height no longer advances.

The captured failure at height 202/203 proves this sequence. Block 202 was
timestamped at `2026-08-19 10:22:02 UTC` but was committed and logged at
`10:22:04.379 UTC`. After the production loop's next two-second sleep, block
203 was already at the four-second slot boundary. Eligibility therefore moved
from Bob to offline Alice and could never return to Bob.

## Impact

- Chain height stops advancing indefinitely.
- Submitted actions can still be accepted into the RPC mempool but cannot be
  included in blocks.
- The explorer eventually reports that no new block has been observed.
- The indexer and APIs remain operational but have no new chain data to serve.
- `systemctl status arxd` continues to report `active (running)`, so process
  supervision does not detect the chain-level failure.
- Restarting `arxd` without deleting its state is not expected to recover the
  blocked height because proposer eligibility is derived from the persisted
  parent block and current elapsed time.
- Deleting all chain data recovers production only temporarily by returning
  the chain to genesis.

## Evidence

### The deployed chain has two validators

The live RPC endpoint returned:

```json
[
  "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz",
  "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5"
]
```

These are:

| Validator | Address | Running validator node |
| --- | --- | --- |
| Alice | `arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz` | No |
| Bob | `arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5` | Yes |

Startup also reported `validators=2`, confirming that this validator set came
from the genesis snapshot embedded in the deployed binary.

The local working copy of `arxd/node/specs/devnet.json` currently removes
Alice from the validator set, but that is an uncommitted local change and is
not present in the installed VPS binary.

### First observed stall

The first captured incident stopped after block 934:

```text
16:46:51  block 931
16:46:55  block 932
16:46:57  block 933
16:47:04  block 934
             no block 935
```

The same `arxd` PID remained active for approximately 17 hours. RPC continued
to accept an action, demonstrating that the process had not crashed.

### Reproduced stall

After a full reset, the problem reproduced at height 202:

```json
{
  "chain_name": "arxium-devnet",
  "tip_height": 202,
  "tip_hash": "0xbcbcaab37136e54626ff6cb02c334e57ab9df5569018725a469260e66d733f85"
}
```

The tip block was:

```json
{
  "height": 202,
  "timestamp": 1787134922,
  "actions": [],
  "proposer": "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5"
}
```

Unix timestamp `1787134922` is `2026-08-19 10:22:02 UTC`. The journal recorded
completion later:

```text
2026-08-19T10:22:04.379562Z INFO produced block 202
```

At `10:29:05 UTC`, the direct node RPC still reported height 202. This proves
that the explorer warning reflected an actual chain halt rather than an
indexer connectivity problem.

### Alternating cadence identifies the missing validator

Before the stall, block production alternated consistently:

```text
odd height:  approximately 2 seconds
even height: approximately 4 seconds
```

Addresses are sorted before selecting a proposer. Alice sorts first and Bob
second. With two validators:

```text
even height primary: Alice (offline)
odd height primary:  Bob (online)
```

Bob therefore produced odd heights in his primary slot and even heights only
after Alice's four-second timeout.

## Technical root cause

### 1. Eligibility advances once and then becomes permanent

`core/primitives/src/consensus.rs` calculates the fallback index as:

```rust
let primary = (height as usize) % sorted.len();
let skip = ((elapsed_secs / slot_duration_secs.max(1)) as usize)
    .min(sorted.len() - 1);
Some(sorted[(primary + skip) % sorted.len()].clone())
```

The `.min(sorted.len() - 1)` cap means that, after all validators have been
considered once, the final fallback remains eligible forever. There is no new
round and no opportunity for an earlier validator to become eligible again.

For height 203, where Bob is primary:

| Elapsed from block 202 | `skip` | Eligible validator |
| --- | ---: | --- |
| 0–3 seconds | 0 | Bob |
| 4 seconds or more | 1 | Alice forever |

The unit test currently codifies this behavior by asserting that the last
validator remains selected even after 1,000 seconds. That behavior prevents
liveness when the selected fallback is offline.

### 2. The production loop silently skips when Bob is not eligible

`arxd/node/src/produce.rs` performs the eligibility check and executes a
silent `continue` when another validator is selected:

```rust
Some(_) => {
    drop(guard);
    continue;
}
```

There is no warning, gauge, or structured reason showing that production is
being skipped. This is why the journal ends immediately after the final block
without reporting an error.

### 3. Block processing time consumes the next validator window

The loop sleeps for two seconds at the beginning of every iteration. Block
timestamps are captured before `produce_block` completes, and storage uses a
synchronous RocksDB write:

```rust
opts.set_sync(true);
self.db.write_opt(batch, &opts)?;
```

Synchronous persistence is appropriate for durability, but its latency is not
included in the scheduling model. A slow `fsync`, RocksDB compaction, host
scheduling delay, or lock wait can consume part of the next slot.

The reproduced incident followed this exact timeline:

```text
10:22:02       block 202 timestamp captured
10:22:04.379   block 202 commit completed and was logged
~10:22:06.379  production loop wakes after its next two-second sleep
4+ seconds     elapsed according to block 202's timestamp
               height 203 eligibility moves from Bob to Alice forever
```

The block contained no actions, so transaction execution was not responsible
for the delay. Storage latency or process scheduling is the likely trigger.
Such a delay should be tolerated by consensus and must not permanently stop
the chain.

### 4. Deployment configuration makes the liveness defect reachable

The genesis set declares two validators, but the deployment runs only Bob.
The consensus implementation therefore depends on Bob taking over every Alice
slot and never missing his own one-time slot. This is too fragile for a real
host, especially one also running Postgres, Redis, Nginx, the indexer, APIs,
and the frontend.

## Findings that are not the root cause

### Indexer sync warning

The warning below does not stop block production:

```text
The remote supports none of the requested protocols
```

The indexer supports `/arxium/sync/1` for outbound requests. When `arxd` tries
to initiate the same protocol toward the indexer, the indexer does not accept
it inbound. This is noisy asymmetric protocol behavior, but the chain's local
production loop does not depend on receiving a sync response from the indexer.

### Gossip subscription warning

Warnings such as the following are also secondary:

```text
NoPeersSubscribedToTopic
```

The indexer subscribes to block gossip but not necessarily action or
precommit topics. These warnings explain failed gossip publication to that
peer; they do not prevent the local block from being produced or committed.

### systemd

The systemd unit behaves as configured. The process remains alive, so
`Restart=always` is never activated. This is an application-liveness failure,
not a process-liveness failure.

## Recommended remediation

### Immediate mitigation for the current devnet

The current deployment runs one validator, so genesis should contain one
validator until a second validator node is intentionally deployed.

1. Build and install `arxd` from the source containing only Bob in
   `arxd/node/specs/devnet.json`.
2. Perform one coordinated chain reset because changing embedded genesis does
   not alter an existing RocksDB validator snapshot.
3. Reset/reindex the explorer database so it follows the new chain from
   genesis.
4. Preserve Bob's `validator.key` so its validator identity remains the one
   declared in genesis.
5. Verify startup reports `validators=1`.
6. Verify `GET /validators` returns only Bob.
7. Leave the node running long enough to cover storage flush/compaction cycles
   and confirm height continues advancing.

With a one-validator set, `sorted.len() - 1` is zero, so Bob remains eligible
regardless of elapsed time. This removes the immediate failure mode but does
not repair the consensus algorithm for future multi-validator deployments.

An alternative immediate mitigation is to deploy and maintain a real Alice
validator node using Alice's validator key. That restores the topology
described by genesis, but it requires a second correctly synchronized and
operated validator. It is more operationally complex than declaring the
single validator that actually exists.

### Durable consensus fix

Replace the one-pass, permanently capped fallback with explicit repeating
rounds. A straightforward deterministic model is:

```rust
let round = elapsed_secs / slot_duration_secs.max(1);
let offset = (round as usize) % sorted.len();
Some(sorted[(primary + offset) % sorted.len()].clone())
```

For two validators and a four-second slot, height 203 would then behave as:

| Elapsed | Eligible validator |
| --- | --- |
| 0–3 seconds | Bob |
| 4–7 seconds | Alice |
| 8–11 seconds | Bob |
| 12–15 seconds | Alice |

If Alice is offline, Bob regains eligibility after one complete rotation
instead of the height becoming permanently impossible.

This change must be treated as a consensus-rule change because both live block
production and historical block acceptance call `eligible_proposer`. All
validator binaries must run the same rule before using it on a shared network.

### Scheduling improvements

The consensus fix should not depend solely on making slots longer. Increasing
the slot duration reduces the frequency of the failure but does not remove the
permanent-liveness defect.

Recommended scheduling improvements are:

- Schedule ticks from a monotonic deadline rather than always sleeping a
  fixed duration after the previous iteration finishes.
- Capture the block timestamp as close as practical to signing/commit so time
  spent preparing a block does not unnecessarily consume the next slot.
- Keep synchronous durable writes unless durability requirements are changed
  deliberately; consensus should tolerate normal storage latency.
- Define and validate timestamp monotonicity and acceptable future-clock drift
  explicitly, because proposer eligibility depends on block timestamps.
- Consider a slot duration comfortably above expected worst-case commit
  latency, but only as additional safety margin.

### Observability improvements

Add visibility for chain-level liveness:

- Log a rate-limited message when production is skipped, including height,
  elapsed time, round, expected proposer, and local validator.
- Export the current expected proposer and current consensus round as metrics.
- Export a counter for `production_skipped_not_eligible`.
- Alert directly on the node's tip timestamp/height, not only through the
  explorer.
- Add a systemd-compatible health watchdog or external monitor that checks
  chain-height advancement. A simple process-alive check is insufficient.
- Avoid automatic restart as the only remediation: restarting with the same
  persisted blocked height does not restore eligibility under the current
  algorithm.

### Required regression tests

Before deploying the consensus change, add tests for:

1. One validator remains eligible at every elapsed time.
2. Two validators alternate during their initial slots.
3. The primary becomes eligible again after one complete missed rotation.
4. A non-primary online validator repeatedly receives opportunities when the
   other validator is offline.
5. Exact slot boundaries (`3`, `4`, `7`, `8` seconds for a four-second slot)
   select the expected validator.
6. A slow block commit followed by the production loop delay cannot make the
   next height permanently unproducible.
7. `produce_loop` and `accept_block` derive the same proposer from identical
   height, validator set, and timestamps.
8. Multi-validator behavior remains deterministic regardless of the input
   ordering of validator addresses.

An integration test should run two configured validators with only one
process online, inject a delay longer than one slot, and verify that chain
height eventually advances.

## Recommended order of work

1. **Restore devnet stability:** deploy a binary whose genesis contains only
   the validator that is actually running, then perform one coordinated reset.
2. **Implement and test repeating consensus rounds:** remove the permanent
   terminal fallback while preserving deterministic proposer validation.
3. **Improve production scheduling:** prevent commit latency from consuming
   an avoidable portion of the next slot.
4. **Add liveness telemetry:** make future proposer skips and stalled heights
   immediately visible.
5. **Clean up protocol noise:** stop `arxd` from initiating sync toward peers
   that do not support inbound sync, or negotiate peer capabilities.
6. **Reintroduce multiple validators deliberately:** only after every declared
   genesis validator has a running node and the liveness regression tests pass.

## Acceptance criteria

The incident is considered resolved when:

- The deployed validator set matches the validators actually being operated.
- Chain height advances continuously through a prolonged test period.
- Injecting a delay longer than one slot does not permanently stall a height.
- A validator regains eligibility after other validators miss their slots.
- Direct node health monitoring detects a stagnant tip.
- The explorer and node report matching advancing heights.
- All consensus and integration tests pass on every validator build.

## Conclusion

The chain stall is caused by a deterministic consensus-liveness bug exposed by
deployment drift. The one-pass fallback algorithm permanently hands a height
to the last fallback validator, while the deployed genesis includes an offline
validator. Normal synchronous storage latency was sufficient to make Bob miss
his only window for height 203. The process then remained healthy but silently
skipped production forever.

Aligning genesis with the single deployed validator is the fastest safe
devnet mitigation. Repeating proposer rounds, improved scheduling, regression
tests, and chain-level health monitoring are required before the system can
reliably operate with multiple validators.
