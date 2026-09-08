# Arxium node operator runbook

Everything here is grounded in what's actually implemented as of 2026-08-20 — no
aspirational tooling. Where something an operator would want doesn't exist yet
(alerting, automated failover, a `reset` subcommand), it's called out explicitly
rather than assumed.

## Topology

One `arxd` process = one node. A node is a **validator** if started with
`--validator` (it produces blocks on its round-robin turn) or a plain peer
otherwise (accepts/relays blocks only). RPC (`30333`, HTTP) and P2P (`30334`,
TCP+QUIC) are separate listeners — see `core/cli`'s `RunArgs` for every flag.

Production topology (`docker-compose.prod.yml`): Caddy terminates TLS and
reverse-proxies RPC over the private compose network; `arxd`'s RPC port is
never published to the host. P2P (`30334`) is published directly — there's no
TLS-terminating proxy in front of libp2p.

## First-time setup (install script)

The shortest path, and the one to hand someone standing up their first node:

> **Not usable yet — the repository is private.** Both this URL and the
> release assets it downloads return 404 to anonymous requests, and the
> installer does not authenticate. Until the repo is public, copy the
> release tarball across by hand. The installer's own error message says
> the same thing if you run it anyway.

```sh
curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh | bash
```

To read it before running it — recommended, and the reason it's a single
self-contained file:

```sh
curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh -o install.sh
less install.sh
bash install.sh            # add --dry-run first to see every step, touching nothing
```

What it does: resolves the latest GitHub release (`--version vX.Y.Z` to pin
one), downloads the binary **and `SHA256SUMS`, verifying the archive before
unpacking it** (it refuses to install if either the checksum file or a
matching digest is missing), lays out `<base_path>/{bin,config,data}`,
writes `config/arxd.env`, prints this node's validator address, and
generates + installs a systemd unit. Flags: `--base-path`, `--yes`
(non-interactive, all defaults), `--dry-run`.

Releases are `x86_64-unknown-linux-gnu` only. On anything else the script
stops and tells you to `cargo build --release -p arxd` instead; on a Linux
box without systemd it installs everything but the unit and prints the
foreground command.

### Configuration lives in an env file, not a TOML file

`<base_path>/config/arxd.env` is read by systemd (`EnvironmentFile=`) and by
`arxd` itself (clap `env` on every `RunArgs` field). There is no config
parser in `arxd` and no precedence rules to learn beyond one: **a
command-line flag beats the env file**, so a one-off run can override the
installed config without editing it.

```sh
sudo systemctl stop arxd
sudo -u <node-user> ~/.arxium/bin/arxd --rpc-bind 0.0.0.0    # try it
$EDITOR ~/.arxium/config/arxd.env                            # then make it stick
sudo systemctl restart arxd
```

`ARXD_VALIDATOR` and `ARXD_BOOTNODE` take an explicit `true`/`false` — the
value is read, not just the key's presence, so setting one to `false`
genuinely turns it off. `ARXD_BOOTNODES=` left blank means "use the chain
spec's own `boot_nodes`", which is what a devnet node wants.

### Check the validator address before starting

The single most common silent failure is a node whose validator identity
isn't in the chain spec's validator set: RPC comes up, P2P listens, genesis
writes, and the tip never advances — with nothing logged. `install.sh`
prints the address during setup for exactly this reason, and you can ask
again at any time without starting the node:

```sh
arxd keys --base-path <base_path>          # address, BLS key, peer ID, spec entry
arxd validator-key --base-path <base_path>/data   # just the address
```

To add this node to a chain spec, `arxd keys --json` emits the `validators`
entry directly — including `bls_pubkey`, without which the validator produces
blocks but can never vote on finality while still counting toward the quorum:

```sh
arxd keys --base-path <base_path> --json
```

Cross-check it against `curl -s localhost:30333/validators`. If it isn't
there, this node will never propose until a `JoinValidator` action adds it.

## First-time setup (production VPS, Docker)



1. `docker buildx build --platform linux/amd64 -t <you>/arxd:latest --push .`
   from a dev machine — a small VPS (2GB RAM) can run the binary but
   shouldn't compile RocksDB from source (see `docker-compose.prod.yml`'s
   header comment).
2. On the VPS: `cp .env.example .env`, fill in `ARXD_DOMAIN` and
   `ARXD_RPC_TOKEN` (`openssl rand -hex 32`).
3. `docker compose -f docker-compose.prod.yml up -d`.
4. Confirm the node came up clean:
   `docker compose -f docker-compose.prod.yml logs arxd | tail -50` — expect
   `validator identity: <address>`, `p2p identity: <peer id>`, `p2p listening
   on ...`, and no `WARN`/`ERROR` beyond benign `NoPeersSubscribedToTopic`
   (normal until it has gossip peers).
5. **Validator identity must match a `devnet.json`/chain-spec validator
   entry, or this node will never produce a block — silently.** A fresh
   `--base-path` self-generates a random `validator.key`
   (`arxd/node/src/validator.rs::load_or_generate_key`) if none exists. If
   that address isn't in the chain spec's validator set,
   `eligible_proposer` never matches it: RPC comes up, genesis writes, P2P
   listens, and the tip just never advances past height 0 — no error
   logged. Confirmed by hand while load-testing this session (see
   `Implementation_log_2026-08-20.md`). To run this node as a *specific*
   validator, put that validator's known Ed25519 seed (hex, no trailing
   newline) into `<base_path>/validator.key` **before first start**, and
   `chmod 600` it. To onboard a *new* validator that wasn't in genesis, the
   real path is `JoinValidator`/`RegisterBlsKey` actions after the node is
   already up (dynamic validator set, see `README.md`'s Phase 2 section) —
   not editing the chain spec.
6. Register the BLS finality key (separate from the Ed25519 node key) so
   this validator's precommit votes count toward finality quorum:
   `arxd bls-key --base-path <path>` prints the pubkey hex (add `--qr` for
   a terminal QR code), then submit it on-chain:
   `send-tx --from <validator-name> --action register-bls-key --bls-pubkey <hex>`.
7. To let an operator wallet (e.g. Arx-Plus) submit staking actions on this
   validator's behalf without the validator's signing key ever leaving the
   box: `arxd pair --base-path <path> --node <host:port> --token <rpc-token>`
   shows a QR code; scanning it and confirming in the app completes the
   `AuthorizeOperator` action. `--revoke` removes the current operator
   without needing to scan anything.

## Running a custom chain

`arxd`'s only built-in presets are `devnet` and `local` (`arxd chain-info
--list`) — CoreChain's own networks, embedded via `include_str!` so a
downloaded binary runs with no files on disk. Everything else, including a
staging net or a brand-new Spoke Chain, is `--chain <path-to-json>`, which
needs no rebuild:

```
arxd keys --json > validator-entry.json
arxd chain-spec --chain devnet > my-net.json    # edit validators/accounts
arxd chain-info --chain ./my-net.json           # inspect before committing
arxd --chain ./my-net.json                      # run — no rebuild anywhere
```

A preset name is always resolved before falling back to a file path (an
operator's own `staging` spec file resolves fine — it's just never confused
for a preset unless something is actually registered under that name).

### Distributing a chain as a raw spec

A plain spec (`my-net.json` above) is the human-authored source of truth, but
every node that boots it re-derives genesis state independently — fine for a
handful of nodes, wasteful for distributing a network to hundreds of them, and
it leaves nothing to eyeball-verify against a published state root before
booting. `arx-spec-builder` converts a plain spec into a self-contained raw
one — the exact encoded storage entries, plus the state root a node must
reach after installing them:

```
arx-spec-builder build --chain ./my-net.json --raw --output my-net-raw.json
arx-spec-builder inspect --chain my-net-raw.json   # chain name, state root, entry count
arxd --chain ./my-net-raw.json                     # boots identically to the plain spec
```

A plain and raw spec for the same chain produce the same genesis hash (used
as the gossip-topic suffix), so nodes booted from either representation
interoperate on the same network. A raw spec is validated against its own
declared `state_root` at boot — installing it and reaching a different root
is a fatal error, not a silent divergence.

## Health checks

- `GET /status` → `{chain_name, tip_height, tip_hash}` (`503` if genesis
  hasn't written yet, `500` on a storage read error — either is worth
  investigating immediately, not retrying blindly).
- `GET /metrics` → Prometheus text format. Key series (see `arxd/node/src/lib.rs`
  and `produce.rs`): `arxium_tip_timestamp_seconds` (gauge — **the one to
  alert on**, see below), `arxium_tip_height` (gauge — should climb roughly
  every `BLOCK_INTERVAL`, 2s), `arxium_is_expected_proposer` (0/1),
  `arxium_consensus_round`, `arxium_production_skipped_not_eligible_total`,
  `arxium_blocks_produced_total` /
  `arxium_blocks_accepted_total` / `arxium_blocks_rejected_total` (counters),
  `arxium_mempool_pending_actions` (gauge), `arxium_block_production_errors_total`,
  `arxium_rpc_requests_total` (per-endpoint, `core/rpc/src/lib.rs`).
  **No dashboard or alerting is wired up yet** — this is `curl`-and-read
  territory until one exists; don't assume a Grafana board is already
  deployed.
- Tip not advancing is the #1 symptom to watch. Cross-check against the
  validator-identity gotcha above before assuming it's a deeper bug —
  that's the single most likely cause on a freshly (re)provisioned box.

### Sync throughput and scan cost (measurement, not alerting)

These exist to turn two open decisions into numbers rather than intuitions:
whether `CF_MERKLE` pruning and snapshot sync belong in this phase, and which
of the storage prefix scans need an index. Nothing here is worth an alert
yet — read them during the acceptance runs and the soak.

Sync (`arxd/network/src/lib.rs`, recorded per applied page):

- `arxium_sync_blocks_applied_total` (counter) and `arxium_sync_page_seconds`
  (histogram) — throughput, either as a ratio or as `rate()` over wall clock.
- `arxium_sync_blocks_per_second` (histogram) — the same number recorded
  directly per page, so a single page's throughput is readable without
  combining two series.
- `arxium_sync_time_to_tip_seconds` (gauge) — from the moment this node
  noticed it was behind to reaching the highest tip any peer advertised.
  Re-armed afterwards, so a node that falls behind again measures that too.
- `arxium_sync_blocks_behind` (gauge) — the live gap. This is the one that
  becomes an alert once a target for it exists.

```promql
# blocks/sec while catching up
rate(arxium_sync_blocks_applied_total[1m])
# time-to-tip at a few chain lengths — the pruning decision
arxium_sync_time_to_tip_seconds
```

Storage scans (`core/storage/src/lib.rs`), labelled `scan=` with
`bls_pubkey_owner`, `current_round`, or `unbonding_due`:

- `arxium_storage_scan_total`, `arxium_storage_scan_rows`,
  `arxium_storage_scan_seconds`.

Rows is the number that grows; seconds is what it costs. An index is
justified when both move, not when either looks large on its own.
`unbonding_due` is the one to watch first — it is the only one on the
per-block path, and the only one whose rows grow with users rather than with
the validator set.

```promql
histogram_quantile(0.99, rate(arxium_storage_scan_rows_bucket[5m]))
histogram_quantile(0.99, rate(arxium_storage_scan_seconds_bucket[5m]))
```

### Detecting a stall

**Alert on `arxium_tip_timestamp_seconds`, not on `arxium_tip_height`.**
A stalled chain holds the height gauge at a constant value, which is
indistinguishable from a chain nobody is transacting on unless you diff it
over time. The tip's own timestamp makes it one expression:

```promql
time() - arxium_tip_timestamp_seconds > 120
```

A 2s block interval means 120s is ~60 missed blocks — comfortably past any
normal `fsync` or compaction hiccup. Without a Prometheus server, the same
check by hand:

```sh
curl -s localhost:30333/metrics | grep '^arxium_tip_timestamp_seconds'
# compare against: date +%s
```

**Do not alert on the systemd unit.** `arxd` stays healthy through a stall —
`systemctl status arxd` reported `active (running)` for ~17 hours during the
original incident. `Restart=always` is not a remedy either: restarting
against the same persisted height changes nothing. This is an
application-liveness failure, which process supervision cannot see.

**A fresh node reports `arxium_tip_timestamp_seconds 0` until it has a block
past genesis.** Genesis carries a synthetic timestamp of 0, so the stall
expression above fires immediately on a node that never produces. That is
intended, not a false positive — it is exactly the validator-identity gotcha
above, caught in seconds instead of after an hour of silence.

### Is the chain finalizing?

Producing blocks and finalizing them are separate, and a chain can do the
first indefinitely while doing none of the second. A validator precommits only
if it has a **registered BLS key**, which is a manual step (`arxd bls-key`
then `register-bls-key`, step 6 of first-time setup) — genesis carries no
keys. Nothing enforces it, so a set can be entirely healthy for block
production and structurally unable to reach a finality quorum.

```sh
curl -s localhost:30333/finality
```

```json
{
  "finalized_height": null,
  "tip_height": 4210,
  "blocks_behind_tip": null,
  "validators": 2,
  "validators_with_bls_key": 0,
  "quorum": 2,
  "quorum_reachable": false
}
```

A validator's BLS key is bound to its registration — `JoinValidator` carries
it, and genesis validators declare `bls_pubkey` in the chain spec — so a set
built either way can vote. A chain spec whose validators predate that field
logs a warning per keyless validator at genesis and needs a `RegisterBlsKey`
action to recover.

**`quorum_reachable: false` means no amount of waiting will finalize
anything** — fewer validators hold a BLS key than quorum requires. Fix it by
registering keys, not by restarting anything. The same numbers are exported
for alerting:

```promql
arxium_validators_with_bls_key < arxium_finality_quorum
```

`finalized_height` climbing but `blocks_behind_tip` growing steadily is the
different failure: votes are being produced and are not arriving, which points
at gossip rather than configuration.

### Why this node isn't producing

Three signals, in the order worth checking:

- **`arxium_is_expected_proposer`** (0/1) — whether it is currently this
  node's turn. Pinned at 0 while the tip is stale means this node is not in
  the rotation at all: check `GET /validators` against
  `arxd validator-key --base-path <base_path>/data`.
- **`arxium_production_skipped_not_eligible_total`** — climbing is normal on
  a multi-validator chain (it is simply someone else's turn). Climbing *while
  the tip is stale* is the stall signature.
- **`arxium_consensus_round`** — which rotation round the current wait is in.
  0 means the primary still holds its slot; a climbing round means slots are
  being missed and eligibility is rotating on looking for someone alive.

The log carries the same picture, rate-limited to once every 30s so it
doesn't bury everything else:

```text
INFO not producing height 1: round 0 belongs to arx1syu…, this node is arx1wx0… (0s since the parent block)
WARN not producing height 431: 47s since the parent block (round 11) — expected proposer is
     arx1syu…, this node is arx1wx0…. Nothing has produced for several rotations; the chain
     may be stalled.
```

The escalation from `INFO` to `WARN` happens once the silence passes ten
slots, which is several full rotations — past the point where "someone
else's turn" explains it.
- `GET /validators` — current validator set, useful to confirm this node's
  identity is actually a member before worrying about why it isn't
  producing.

## Logs

`docker compose -f docker-compose.prod.yml logs -f arxd`. Structured via
`tracing`; no `RUST_LOG` override is wired into the compose files, so it
runs at whatever the binary's default filter is — check `arxd/src/main.rs`
if you need to raise verbosity, and set `RUST_LOG` in `.env` /the compose
`environment:` block (not currently present, would need adding).

## Backups

`scripts/backup-node.sh <data-dir> <backup-dir> [keep-count]` tars up the
node's whole data directory (RocksDB `data/`, `snapshots/`, `validator.key`,
`validator.bls.key`, `network.key`) and prunes old backups beyond
`keep-count` (default 14). **Run it against a stopped node**, or accept it's
a fuzzy/non-atomic snapshot of a live RocksDB directory — the script itself
doesn't stop anything for you. **Copy the resulting tarball off-box**
(rsync/rclone/provider snapshot) — a backup living on the same disk it's
backing up doesn't survive a disk failure, which is the whole point of
having one.

### Restore

1. Stop the node (`docker compose ... stop arxd` or `arxd` process kill —
   RocksDB allows exactly one writer per DB directory, a second process
   pointed at the same `--base-path` will fail to open it).
2. Untar the backup into a fresh (or emptied) `--base-path`.
3. Start the node normally. It reads the tip from the restored DB —
   nothing special to invoke.
4. If instead the *box* is gone and only `validator.key` survived (e.g. it
   was backed up separately), a fresh node with that key can rejoin and
   catch up via P2P sync **only if there are reachable peers/bootnodes to
   sync from** — this is a single-validator devnet's real limitation right
   now: with one validator and no peers, there is nothing to sync *from*,
   so losing the data directory without a data backup means losing chain
   history, not just re-deriving it from the key.

## Incident playbooks

**Node up, tip stuck.**
1. Check `GET /validators` — is this node's own address actually a member?
   If not: it's a peer, not a producer, working as intended; add it via
   `JoinValidator`, not by editing config.
2. If it should be a validator and isn't producing: check logs for `no
   validators registered, skipping block production` — means the on-chain
   validator set is empty (shouldn't happen post-genesis, worth escalating,
   not a config issue).
3. If it's a validator, is registered, and still stuck: check `p2p
   listening on ...` came up and (for a multi-node deployment) that peers
   are actually connected — a validator that's lost all peers can't see
   competing blocks but also can't be seen producing them by anyone else,
   which looks identical to "stuck" from outside.
4. Compare `validator.key`'s derived address (log line `validator identity:
   <address>` on startup) against the chain spec / `GET /validators` byte
   for byte. This was the actual root cause the one time this was hit
   during this session's load testing.

**Client (wallet, indexer, script) getting `429 Too Many Requests`.**
`core/rpc`'s per-IP rate limiter now tracks reads and writes on separate
budgets (fixed this session — previously a write burst could starve a
client's own status-check reads): writes (`POST /actions`, `POST /pairing`)
are capped at 60/60s per IP, reads (everything else) at 600/60s per IP, both
sliding 60s windows, in-memory and per-node (not shared across a multi-node
deployment, and resets on restart). A legitimate integrator hitting the write
cap should back off and retry, not treat it as a node health problem. If
reads are 429ing under *normal* (non-burst) traffic, that's worth raising —
600/min is generous for polling, not for e.g. an indexer doing a full
historical crawl.

**Suspected validator fault (double-sign, downtime) needing a manual slash.**
`circuit_staking::apply_slash` is deliberately not reachable from any
`ActionPayload`/RPC path — this is manual/out-of-band until a real fault
detector exists. `scripts/admin-slash --base-path <stopped-node-path>
--validator <address> --amount <u128> --reason double-sign|downtime` opens
the DB directly and writes the slash as one atomic batch. **Requires the
target node process to be stopped first** (same single-RocksDB-writer
constraint as restore). Downtime slashing (0.01%/missed slot) does happen
automatically on-chain via `apply_downtime_slash` — this manual tool is only
for cases that need an out-of-band decision, e.g. confirmed double-sign
evidence.

**Disk full / DB won't open on startup.** Not yet exercised or scripted —
no documented procedure exists. At minimum: don't delete anything under
`--base-path` without a backup first (see Backups above); RocksDB corruption
recovery is DB-specific troubleshooting, not covered here.

## Restarts & upgrades

1. `scripts/backup-node.sh` first — always, even for a routine upgrade.
2. `docker compose -f docker-compose.prod.yml pull && docker compose -f
   docker-compose.prod.yml up -d` (pulls the new image, recreates the
   container; `restart: unless-stopped` means a crash also auto-restarts on
   the *old* image until you explicitly pull).
3. Startup verifies the tip block's signature before building on it
   (`README.md`'s Phase 1 hardening notes) — a corrupted/tampered tip fails
   to start rather than silently building on bad state, so a clean restart
   is the confirmation the upgrade didn't corrupt anything.
4. Watch `GET /status` tip_height resume climbing and logs for the first
   post-restart `produced block N ...` / `accepted gossiped block N ...`
   line before considering the restart done.

## Rotating the RPC bearer token

Update `ARXD_RPC_TOKEN` in `.env`, `docker compose -f
docker-compose.prod.yml up -d` to recreate `arxd` with the new value. Every
client (Arx-Plus's Node Settings, `send-tx --token`, `load-test --token`,
monitoring scripts) needs the new token before the old one is retired —
there's no dual-token grace period, the check is a single constant-time
comparison against one configured value (`core/rpc/src/lib.rs`).

## Fault evidence verification

When a validator observes another validator equivocate or a proposed
block's execution disagree with its own, it writes a signed JSON evidence
artifact and serves it over its own RPC — no shell access to the node
required to check it:

1. `GET /evidence` lists the artifact filenames a node currently has.
2. `GET /evidence/{id}` fetches one artifact's raw JSON.
3. Check the artifact's `genesis_hash` against a genesis-hash registry you
   trust independently of the node that served it — the artifact's
   signatures being valid only proves internal consistency, not that
   it's about a chain you should care about.
4. Run `arx-verify <file>` (see `tools/arx-verify/README.md`) to check the
   signatures and get a `VALID`/`UNRESOLVED` verdict.

## Two-node fault-injection acceptance harness

`scripts/two-node-fault-harness.sh` boots `NUM_VALIDATORS` (default 4) local
validators from a throwaway genesis and corrupts one node's own state_root at
a fixed height, to exercise the dissent/evidence/slash path against real
processes instead of a mocked executor. It needs nothing installed beyond
`jq` and `curl`; everything else (keys, genesis, all nodes) is generated into
a `mktemp -d` scratch directory it cleans up on success and leaves behind
(path printed) on failure.

```sh
scripts/two-node-fault-harness.sh                 # 4 validators, fault at height 5 (defaults)
NUM_VALIDATORS=2 scripts/two-node-fault-harness.sh  # original two-node case
FAULT_HEIGHT=20 scripts/two-node-fault-harness.sh  # override the fault height
```

**Why 4, not 2, by default.** `quorum(n) = 2n/3 + 1` (`core/primitives/src/consensus.rs:20`)
is 2 at n=2 — the faulty node's own vote is required for any quorum, so a
two-node run can never demonstrate the honest side outvoting a faulty one.
At n=4, quorum is 3 and the three honest nodes can reach it without the
faulty node. See the 2026-09-06 re-run below for what that did and didn't
settle.

**The flag it exercises does not exist in a normal build.** `arxd`'s
`--inject-fault-at-height` / `ARXD_INJECT_FAULT_AT_HEIGHT` is compiled in
only with `cargo build --features fault-injection`, and even then the node
refuses to start unless the resolved chain spec's `chain_name` is exactly
`arxium-fault-injection-harness` — not `devnet` (the real `--chain devnet`
preset resolves to `chain_name: "corechain"` with real public boot nodes; it
is a shared network, not a sandbox, so a literal `"devnet"` check would have
been the wrong guard). The harness's own throwaway genesis is the only spec
that can ever satisfy this.

**The validator-key gotcha applies here too.** `arxd keys --base-path <dir>
--json` must be run once per node *before* that node's first start, writing
`validator.key`/`validator.bls.key` into that exact `--base-path` — the
harness script does this itself for both nodes and merges both `ValidatorEntry`
outputs straight into the genesis JSON's `validators` map. If you're adapting
the script (different base paths, reusing a directory from a previous run,
etc.), regenerating keys against a *different* base-path than the one the
node is later started with reproduces the single most common silent failure
in this codebase: RPC comes up, P2P listens, genesis writes, and the tip
never advances, with nothing logged — see "Check the validator address
before starting" above.

**Run 2026-09-06, two validators: the chain deadlocks instead of slashing.**
A live run confirmed fault injection, dissent, and evidence-artifact
generation all fire correctly — node A rejects B's corrupted block 5
(`StateRootMismatch`), signs a dissent, and successfully pushes a
`SubmitExecutionFault` action into its own mempool. But A's tip then sticks
at height 4 permanently: it has no local block 5 to build on (it rejected
the only one offered), round-timeout votes for height 6 are dropped for
lacking a parent at 5, and there's no reorg/rollback to let a different
proposer retry height 5. B's fault action sits in A's mempool forever, never
mined, so the on-chain slash never lands.

**This was originally logged as "Stage 3 unreachable without
reorg/rollback." That claim was too strong — `quorum(2) = 2` means both
validators, including the faulty one, must agree before *anything* advances
past height 5; the deadlock is required by the math at n=2 regardless of
reorg/rollback. It says nothing about whether Stage 3 is reachable when the
honest side has an actual quorum majority (n=4, quorum 3), which is the case
that matters. Also worth separating: A never *committed* height 5, it
rejected the proposal outright — so "reorg/rollback," which undoes an
already-committed block, was never the applicable mechanism here. What was
missing is the honest majority driving a round/view change to re-propose
height 5 itself, which is a different (and already-implemented) code path.**

**Re-run 2026-09-06 at 4 validators (3 honest, 1 fault-injected) —
inconclusive, and it surfaced a separate, more disruptive bug.** The harness
(now `NUM_VALIDATORS`-parametrized) was re-run roughly 15 times at n=4, with
extra RPC probing on a handful of runs to pin down what's actually
happening. Two distinct, non-overlapping failure shapes showed up, plus one
clean pass that wasn't a real test of anything:

- **Asymmetric stall, no crash logged (1 run, likely not a distinct bug —
  see below).** 2 of 3 honest nodes logged "stuck at tip height 4" exactly
  as in the n=2 case, the 3rd reached height 11, zero panics in any of the
  four logs. A first pass called this "a sync/gossip convergence gap" —
  premature, and a reviewer correctly pushed back twice on it, each time
  cheaply and correctly:
  - First, on the arithmetic: this protocol isn't continuous-quorum BFT.
    `core/executor/src/lib.rs:420-442` only requires a quorum-backed
    `RoundCertificate` at the *specific height* a round advances past 0;
    every later height is unilateral re-execution needing no live quorum. So
    "1 node needs 3 live co-signers at every height 5-11" was never the
    right model — that argument doesn't hold, in either direction.
  - Second, on what "stuck" actually means: the log line is
    `arxd/network/src/lib.rs:758`, and reading its surrounding code shows
    it's explicitly per-peer, not per-node — `"giving up on {peer} until it
    reconnects or another peer reports progress"`. A node that gives up on
    one peer can still advance via a different peer or its own production.
    Confirmed this live: in one run a node logged "stuck at 4" early on and
    the harness's own default 58s `CHAIN_TIMEOUT` later reported it at
    height 10 (one short of the target) — i.e. it had recovered and kept
    going well past the point its log made it look permanently wedged.
    That makes the original 2-stuck-1-advanced result far less likely to be
    a distinct bug: it's the more mundane explanation that a fixed,
    short test timeout caught two recovering nodes mid-recovery, not that
    they were stuck forever. Not fully proven (never reproduced the exact
    original case again to confirm those two specific nodes would have
    caught up given more time), but enough to stop calling this an open
    anomaly needing a separate fix.
- **Symmetric stall, caused by a crash (reproduced multiple times, and now
  root-caused to the actual assertion, not guessed at).** A
  `libp2p-request-response-0.29.0` internal panic
  (`assertion left == right failed`, `lib.rs:678`) kills the networking task
  on whichever node it hits — including, in one run, node 0 itself within
  milliseconds of startup, before it ever got to propose anything, and in
  another, an honest node partway through the run. When it takes out one
  honest node's networking, the remaining live honest count drops to 2,
  below `quorum(4) = 3`, and everyone left standing stalls for the rest of
  the run — a real, arithmetic-grounded liveness failure, just one caused by
  a crash rather than by anything in the finality logic. It fires often
  enough (multiple times across ~25 runs total, at unpredictable points
  including immediately at startup) to dominate most n=4 attempts.
  Captured a full `RUST_BACKTRACE=full` of it: the panic is inside
  `libp2p_request_response::Behaviour::on_connection_closed`, called
  directly from an ordinary `SwarmEvent::ConnectionClosed` — i.e. entirely
  inside the upstream library's own per-connection bookkeeping, triggered by
  a plain disconnect. **This retracts the earlier guess** that
  `arxd/network/src/lib.rs:592-597`'s dropped `ResponseChannel` on a decode
  failure was the cause — a reviewer correctly pointed out that dropping a
  channel is explicit, legal `libp2p-request-response` API surface (it
  becomes an `InboundFailure` on the peer's side, not a panic), and the
  backtrace confirms the crash has nothing to do with that code path.
  Checked whether a dependency bump sidesteps it: `libp2p = "0.56.0"` (a
  `^0.56.0` constraint) is already the latest 0.56.x per
  `cargo update -p libp2p --dry-run` (zero updates available), and
  `cargo search libp2p` shows 0.56.0 is the latest published release full
  stop — there is no newer version to bump to right now. This is a live,
  unfixed bug in the current latest release of a core dependency; fixing it
  means either an upstream issue/patch or working around the specific
  connection-close path in `arxd/network`, not a version bump.
- One run had all 3 honest nodes converge cleanly to height 11 while node 0
  sat at height 0 — but node 0's own log showed the same libp2p panic in the
  first half-second after startup, before `ARXD_INJECT_FAULT_AT_HEIGHT` ever
  had a chance to fire. That's 3 honest validators reaching quorum with no
  adversary actually present, not a pass of the fault-injection scenario.
- No run reached a slash. Even the cleanest run, the reference node's
  evidence directory stayed empty — consistent with the known
  evidence-resubmission dedup gap (`core/evidence/src/lib.rs:383`,
  `ponytail:`-flagged, see item 3 in the implementation log), but every n=4
  run so far has had a crash or a preempted-fault confound in it too, so
  this hasn't been isolated as the sole cause yet either.

**Update: got a clean pass. The libp2p panic is a `debug_assert` — build
`--release` and it's gone, and that unblocked a real signal today.**

The panic is `rust-libp2p`'s own known, open, unfixed issue — not ours.
Matches two upstream reports: **#4773** (open since 2023-10-31, same
assertion at the same `on_connection_closed` site, triggered by multiple
in-flight dials with some denied — our mDNS-plus-explicit-bootnode topology
fits this) and **#6601** (opened 2026-09-03, a PR fixing a connection-
tracking desync when a sibling `NetworkBehaviour` denies a connection that
`request-response` already recorded — matches our backtrace's call site
exactly, and is unreleased). Both name the panicking check as a
`debug_assert_eq!`, meaning it **compiles out entirely in release builds**.
Confirmed directly: `cargo build --release -p arxd --features
fault-injection`, then 14 n=4 harness runs against the release binary — zero
panics, versus a roughly-40% crash rate across ~25 debug-build runs
beforehand. Important caveat from the upstream report itself: `--release`
hides the check, it doesn't fix the underlying inconsistent connection
state — request-response's internal bookkeeping is still wrong when this
fires, silently, in production. This unblocks trustworthy testing; it is
not a networking-layer fix. No local dependency fix is available today
(`cargo update -p libp2p --dry-run` and `cargo search libp2p` both confirm
`0.56.0` is the current latest release) — the real fix is upstream (#6601
merging) or a local `[patch.crates-io]` to its branch if that's worth the
risk before it ships.

With the crash out of the way, one release-mode run finally completed the
full adversarial scenario for the first time: real dissent, real gossip
propagation, no crash, chain reached height 11. It also caught a bug in the
**harness itself**: the "node 0 did not fabricate a counter-accusation"
check asserted node 0's `/evidence` directory was empty, and this run
correctly failed that assertion — node 0 had accumulated three
`<height>-disagreement-<voter>.json` files. Reading `core/evidence/src/lib.rs:352`
showed why that's expected, not a violation: the evidence-watcher writes a
local copy of *any* `ExecutionDisagreement` it observes, regardless of who
authored the underlying dissent — so once gossip actually propagates the
three honest validators' dissent network-wide, node 0 (still a live peer)
receives and locally records copies of it too, same as everyone else. The
actual security property the recursion guard cares about — no honest
validator ends up slashed by node 0's own fabricated action — is already
covered by the adjacent "honest nodes' stakes are untouched" check, so the
flawed assertion was removed from `scripts/two-node-fault-harness.sh` rather
than reworked. It had simply never been exercised against a run with full
dissent propagation before today.

That same clean run also reproduced the partial-slash symptom described
here previously — node 0's `active_amount` dropped but didn't reach zero,
no honest node's evidence endpoint showed a complete `SubmitExecutionFault`
— and that earlier write-up attributed it entirely to
`core/evidence/src/lib.rs:383`'s missing local dedup. **That diagnosis was
incomplete.** Tracing the actual mempool errors (`insufficient balance for
the action fee`, immediately preceding every `duplicate action ... at nonce
0`) back to the harness's genesis showed `accounts: {}` — every validator
had stake but zero *spendable* balance, and `SubmitExecutionFault` costs
`ACTION_FEE` (`arxd/runtime/src/lib.rs:417`, 1,000,000 IUM) like any other
action. The very first evidence submission was never mined for lack of
funds, which pinned its nonce forever and made every honest validator's
own resubmission look like a self-inflicted collision — a bug-shaped
symptom of a test-fixture gap, not a resubmission storm.

**Funding each validator's account in genesis
(`scripts/two-node-fault-harness.sh`, 100x `ACTION_FEE`) produced the
harness's first fully green run**, and it wasn't a fluke: 4 clean passes
across every run where the fault actually triggered (node 0 has to land
the height-5 proposer slot for the fault to fire at all — roughly 1-in-4 to
1-in-8 of runs, depending on validator address ordering that run). A real
local-dedup fix was still added to `core/evidence/src/lib.rs`'s
`spawn_evidence_watcher` (a `BlockDivergence` event fires once per
dissenting peer observed, not once per height, so without it a healthy
network still submits one redundant on-chain report per extra dissenter)
— covered by
`spawn_evidence_watcher_only_submits_once_per_height_despite_repeat_divergence_events`,
verified to actually fail without the guard before being accepted. But it
was never the release-blocking gap; the funding was.

Three more harness corrections landed alongside this, all from a second
round of review on the item 11 fixes:
- The self-incrimination guard now checks the right thing: it scans mined
  blocks (`/blocks/{height}`) for a `SubmitExecutionFault` sent by node 0,
  rather than the harness's earlier proxy checks. "Honest nodes' stakes are
  untouched" only covers culprit resolution, not this — they're different
  properties, and the `PASS` message was overclaiming both.
- `PASS` no longer claims the recursion guard held. Nothing in this
  single-fault scenario nests a fault inside a fault, so it's never
  exercised here; a real failure there would show up as stack exhaustion,
  not a stake or action-level symptom this harness could catch.
- The harness now builds and runs `--release` itself (previously this was
  only a runbook instruction) — a debug build is no longer an option a
  future run of this script can silently pick.

**Two more corrections landed on top of this, from a second round of
review.** The local dedup guard was keyed on height alone — wrong, because
a round change can put a *different* proposer at the same height, and the
chain-level `EvidenceMarkerKey` (`core/circuit/src/lib.rs`) keys on
`(height, proposer)` for exactly that reason; a local guard stricter than
the chain accepts would silently and permanently drop a second, legitimate
fault report. Fixed to match. Separately, re-verifying that fix surfaced
that the harness's fixed 58s `CHAIN_TIMEOUT` was undersized for the actual
disputed-height recovery case (needs at least one full production
`ROUND_TIMEOUT`, 8s, plus real gossip propagation) — sized for the
no-dispute case, not the one this harness exists to test. Confirmed with a
240s-vs-58s comparison (10/10 clean at 240s, most triggered runs timing out
at 58s) and fixed to a flat 240s.

**Net: every open question from items 7-13 is now resolved or closed.** n=2
is quorum degeneracy, not a missing feature. The n=4 asymmetric split is
very likely the per-peer "stuck" semantics plus a short timeout. The libp2p
panic is upstream, dodged via `--release` (now baked into the harness). The
evidence pipeline works end-to-end once validators are actually funded to
pay for their own fault reports and the dedup guard matches the chain's own
notion of "the same fault." `scripts/two-node-fault-harness.sh` is the
acceptance signal Stage 3 was waiting on, and it now passes reliably.

## Divergence recovery — live-proven 2026-09-08

The `68d2b26` divergence-recovery block added four assertions to
`scripts/two-node-fault-harness.sh` on top of the culprit/evidence/slash
checks documented above: the diverged node actually reverts
(`"reverted from height"` in its log), it converges on the same
`state_root` as the honest majority, no action from the honest chain is
lost (every action signature resolves on the recovered node as confirmed or
pending, never 404), and no node reverts below its finalized watermark
(a `HALT:` anywhere is a failure). All prior runs recorded above — the
10-attempt 240s timeout tuning included — predate this block and only
exercised the fault/evidence/slash loop, not rollback.

**First run against the new assertions (2026-09-08) failed, but not on
recovery.** It exposed a pre-existing gap the runbook had already
flagged in passing above ("roughly 1-in-4 to 1-in-8 runs, depending on
validator address ordering") but never fixed: `FAULT_HEIGHT` is only ever
corrupted by whoever *proposes* that height, and the proposer is
`sorted(validator_addresses)[height % n]` — sorted by each validator's
freshly-random generated address. The harness always armed node 0 for a
fixed height without checking node 0 actually held that proposer slot. This
run it didn't; the fault never fired, so the four new assertions passed
(3 of them) or correctly failed (the revert check) on a scenario that never
happened — a clean-looking run with nothing exercised.

**Fixed the same day.** `scripts/two-node-fault-harness.sh` now computes
`FAULT_HEIGHT` *after* generating validator keys: it sorts the real
addresses and slides `FAULT_HEIGHT` forward to the next height where node 0
is guaranteed to be the round-0 proposer, instead of gambling on the
caller's chosen height. (Also had to replace a `mapfile -t` with a plain
word-split array assignment — macOS's default bash is 3.2 and doesn't have
`mapfile`, even under `#!/usr/bin/env bash`.)

**Re-run, same day, full pass — the first live proof this feature works:**

```
reverted from height 5 to 4 in favour of <peer>'s certified chain
(divergence at 5); 0 action(s) returned to the mempool
node 0 agrees with the majority at height 11
  (state_root 0x07b90fd6f7609168d649d84fa16bed7afc1fd44e907bdc599d9fa1b7b3869c95)
no action from the honest chain went missing on node 0
no node reverted below its finalized watermark
```

along with the pre-existing checks: node 0's stake fully slashed, honest
nodes' stakes untouched, an honest node wrote fault evidence, and node 0
never self-incriminated another validator.

**Caveat for future readers:** any run of this script from before the
2026-09-08 fix should be treated as inconclusive on divergence recovery
specifically (not necessarily on the fault/evidence/slash loop, which the
proposer-slot bug doesn't affect the same way, since that loop's checks
tolerate — and log — a non-firing fault as a clear FAIL rather than a
silent pass). If you're citing an old "green run" as evidence rollback
works, check it postdates this fix.

## Known limitations worth an operator's awareness

From `TODO.md`, not yet fixed — not urgent for a single-validator devnet,
but relevant once this runs multi-node or faces adversarial peers:

- **Two-validator chains cannot outvote a faulty validator (not a bug —
  `quorum(2) = 2`).** With only 2 validators, quorum requires both, so a
  node that rejects its peer's block has no way to make progress no matter
  what machinery exists — this is arithmetic, not a missing feature. Confirmed
  live via `scripts/two-node-fault-harness.sh`; see above for what running at
  4 validators (honest majority, quorum outvotes the faulty node) did and
  didn't settle. Whether an honest quorum majority can itself recover from a
  rejected proposal via round/view-change (as opposed to reorg/rollback of an
  already-committed block, which doesn't apply here — nothing was committed)
  is still open, blocked on an unrelated libp2p crash found during the n=4
  re-run (see above) and the evidence-resubmission dedup gap in
  `core/evidence/src/lib.rs:383` (item 3 in the implementation log).
- Reconnecting a peer clears its bad-gossip/sync-failure penalty counters —
  a peer that's about to hit the ban threshold can reconnect and keep
  spamming indefinitely (ban is per-connection, not per-`PeerId`).
- No explicit gossipsub message-size ceiling is set — relying on the
  library default (~64KB); a block that grows past it would be silently
  dropped on the gossip fast path (sync would eventually catch it up, but
  it'd look like blocks "never arrive" via gossip).
- Network observability is a peer-count gauge only — no counters for
  gossip accept/reject rates or bad-gossip disconnects, so exploitation of
  the above would show up in logs before it shows up in any metric.
