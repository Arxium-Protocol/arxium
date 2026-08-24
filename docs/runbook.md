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

## First-time setup (production VPS)

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

## Health checks

- `GET /status` → `{chain_name, tip_height, tip_hash}` (`503` if genesis
  hasn't written yet, `500` on a storage read error — either is worth
  investigating immediately, not retrying blindly).
- `GET /metrics` → Prometheus text format. Key series (see `arxd/node/src/lib.rs`
  and `produce.rs`): `arxium_tip_height` (gauge — should climb roughly every
  `BLOCK_INTERVAL`, 2s), `arxium_blocks_produced_total` /
  `arxium_blocks_accepted_total` / `arxium_blocks_rejected_total` (counters),
  `arxium_mempool_pending_actions` (gauge), `arxium_block_production_errors_total`,
  `arxium_rpc_requests_total` (per-endpoint, `core/rpc/src/lib.rs`).
  **No dashboard or alerting is wired up yet** — this is `curl`-and-read
  territory until one exists; don't assume a Grafana board is already
  deployed.
- Tip not advancing is the #1 symptom to watch. Cross-check against the
  validator-identity gotcha above before assuming it's a deeper bug —
  that's the single most likely cause on a freshly (re)provisioned box.
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
