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

## Known limitations worth an operator's awareness

From `TODO.md`, not yet fixed — not urgent for a single-validator devnet,
but relevant once this runs multi-node or faces adversarial peers:

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
