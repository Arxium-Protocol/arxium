# Arxium

A Layer 0 blockchain node, written in Rust.

Arxium is a proof-of-stake chain built around **circuits** — small, isolated
state-transition modules that validate and propose changes without writing
them. A block's effects are computed by circuits, then committed atomically by
the node. Account transfers, staking, real-world-asset issuance with
compliance gating, and zero-knowledge identity credentials are each a separate
circuit, and the chain that composes them declares its own action type rather
than inheriting a fixed one.

`arxd` is the node daemon. A single binary plays every role — validator, full
node, or bootnode — selected by configuration, not by a separate build.

> The repository is private ahead of launch. Until it is public, the install
> script and release assets below are not reachable anonymously.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh | bash
```

Downloads the latest release and verifies it against the release's
`SHA256SUMS` before unpacking, lays out `~/.arxium/{bin,config,data}`, writes a
configuration file, prints this node's validator address, and generates a
systemd unit. `--dry-run` shows every step without touching the disk.

Add `--with-monitoring` to install release-matched native Prometheus and
Grafana services, alert rules, and the provisioned Arxium Node dashboard under
systemd. Native Grafana uses operator-selected credentials and public HTTPS on
port 3000; Prometheus remains loopback-only. Docker is not required. The
complete native, bring-your-own, and optional Docker paths are documented in
[`monitoring/`](monitoring/README.md).

Prebuilt releases target `x86_64-unknown-linux-gnu`. Everywhere else, build
from source.

### Build from source

Requires a recent stable Rust toolchain, plus `clang`, `cmake` and
`libclang-dev` for RocksDB.

```sh
cargo build --release -p arxd
./target/release/arxd --help
```

## Running a node

Every node joins the network, syncs, and serves RPC. Passing `--validator`
additionally makes it produce blocks on its turn in the rotation — which
requires its address to be in the validator set.

```sh
arxd --base-path ~/.arxium/data                  # full node
arxd --base-path ~/.arxium/data --validator      # validator
```

Configuration comes from flags or the matching `ARXD_*` environment variables,
with flags taking precedence. The installer writes an env file that both
systemd (`EnvironmentFile=`) and `arxd` read directly.

| Flag | Environment | Default | Purpose |
| --- | --- | --- | --- |
| `--base-path` | `ARXD_BASE_PATH` | `~/.arxium` | Keys, chain database, genesis cache |
| `--port` | `ARXD_PORT` | `30333` | HTTP RPC listener |
| `--p2p-port` | `ARXD_P2P_PORT` | `30334` | libp2p listener (TCP + QUIC) |
| `--validator` | `ARXD_VALIDATOR` | `false` | Produce blocks on this node's turn |
| `--rpc-bind` | `ARXD_RPC_BIND` | `127.0.0.1` | RPC bind address |
| `--rpc-token` | `ARXD_RPC_TOKEN` | none | Require `Authorization: Bearer <token>` |
| `--bootnodes` | `ARXD_BOOTNODES` | chain spec | Comma-separated peer multiaddrs |
| `--bootnode` | `ARXD_BOOTNODE` | `false` | Use the well-known seeded network identity |

`arxd` runs in the foreground and logs to stdout. It does not daemonize, write
a PID file, or restart itself — process lifecycle belongs to systemd, and logs
to journald.

### Keys

A node holds up to three identities, each generated on first use and stored
under `--base-path` with owner-only permissions.

```sh
arxd keys             # all three, plus a ready-made chain-spec entry
arxd keys --json      # just the chain-spec entry, for piping

arxd validator-key    # Ed25519 block-signing address — must be in the validator set
arxd bls-key          # BLS finality key
arxd node-key         # libp2p PeerId — the network identity
```

`arxd keys` prints the entry to paste into a chain spec's `validators` map,
built from the same type the spec loader parses. Logs go to stderr, so
`arxd keys --json | jq` works.

`validator.key` is the validator's entire signing identity and has no recovery
path. Back up `<base-path>` — `scripts/backup-node.sh` does this.

An operator wallet can be authorized to submit staking actions on a
validator's behalf without the signing key leaving the machine:

```sh
arxd pair --node <host:port> --token <rpc-token>
```

### Bootstrapping from a snapshot

A new node normally joins by syncing every block from genesis
(`SyncRequest::Blocks`), which gets slower the longer the chain has run. An
existing node can export a checkpoint of its chain data instead:

```sh
arxd snapshot --base-path ~/.arxium --output ./corechain-snapshot
```

A new node then uses a copy of that directory as its data dir (`<base-path>/corechain/data`)
and starts already at that snapshot's tip height, with nothing to replay.

This is a trust-the-source shortcut, not a verified state sync: blocks carry
no state root, so a receiving node has no way to check a snapshot against
what the network actually finalized. Only use one from an operator you
already trust — the same bar as trusting any other out-of-band chain data.

## RPC

HTTP, JSON. Bearer auth and per-IP rate limiting apply when a token is set.
`arxd` speaks plain HTTP — put a TLS-terminating proxy in front of any
non-loopback deployment.

| Endpoint | Description |
| --- | --- |
| `POST /actions` | Submit a signed action |
| `GET /status` | Chain name, tip height, tip hash, finalized height |
| `GET /accounts/{address}` | Balance, nonce, identity hash |
| `GET /accounts/{address}/stake` | Stake allocations and unbonding |
| `GET /accounts/{address}/bls-key` | Registered BLS finality key |
| `GET /actions/{signature}` | Status of a submitted action |
| `GET /blocks` | Bounded range of blocks |
| `GET /blocks/{height}` | Block by height |
| `GET /blocks/by-hash/{hash}` | Block by hash |
| `GET /validators` | Current validator set |
| `GET /finality` | Finalized height, and whether the set can reach quorum |
| `GET /operators/{address}/validators` | Validators an operator may act for |
| `GET /search` | Height, address, or hash — one endpoint, type inferred |
| `GET /min-stake` | Minimum stake to become a validator |
| `GET /action-fee` | Flat per-action fee |
| `POST /pairing` | Begin operator-wallet pairing |
| `GET /metrics` | Prometheus text format |

Submissions are rejected at the boundary for a bad signature or a stale nonce,
before reaching the mempool. Insufficient balance is caught at block
production, since balance can change between submission and inclusion.

The node serves current state and blocks it holds. It deliberately does not
serve per-address transaction history or aggregate queries — those belong to
an indexer reading the chain, not to the node's hot path.

## Actions

| Action | Effect |
| --- | --- |
| `Transfer` | Move balance between accounts |
| `Stake` / `Unstake` | Delegate to a validator; unstaking unbonds over 100 blocks |
| `JoinValidator` / `LeaveValidator` | Enter or leave the validator set; joining carries the BLS finality key |
| `RegisterBlsKey` | Register a BLS key so precommits count toward finality |
| `SubmitEquivocationEvidence` | Report a validator that signed two blocks at one height |
| `VerifyIdentityCredential` | Prove a credential in zero knowledge |
| `AuthorizeOperator` / `RevokeOperator` | Delegate action submission to another account |

## Chain parameters

| Parameter | Value |
| --- | --- |
| Denomination | 1 ARX = 1,000,000,000 IUM |
| Block interval | 2s |
| Slot duration | 4s |
| Action fee | 0.001 ARX |
| Minimum validator stake | 100,000 ARX |
| Unbonding period | 100 blocks |
| Finality | BLS aggregate precommits, 2/3+1 of the validator set |

A validator's BLS finality key is bound to its registration: `JoinValidator`
carries it and registers it atomically, and genesis validators declare one via
`bls_pubkey` in the chain spec. A validator counts toward the quorum whether or
not it can vote, so one without a key would raise the threshold while
contributing nothing to meeting it. `GET /finality` reports how much of the
current set can actually vote, and whether that clears quorum.

These are compile-time constants. Changing one is a coordinated release, not a
runtime setting.

## Architecture

Three layers, with a dependency rule enforced between them: `arxd` depends on
`core` and `circuits`; nothing in `core` may depend back into `arxd`.

| Crate | Responsibility |
| --- | --- |
| `core/primitives` | `Action<P>`/`Block<P>` generic over a chain's payload type, addresses, proposer selection |
| `core/storage` | RocksDB wrapper with typed keys and atomic multi-item batches |
| `core/executor` | Signature verification, action dispatch, block acceptance |
| `core/mempool` | Capacity-bounded pending pool, deduplicated by `(sender, nonce)` |
| `core/rpc` | HTTP ingest and reads, generic over the payload type |
| `core/bls` | BLS12-381 signing, verification, aggregation |
| `core/cli`, `core/genesis`, `core/wire` | Node configuration, genesis bootstrap, wire types |
| `circuits/account` | Balance and nonce transitions |
| `circuits/staking` | Staking, unbonding, slashing, block rewards |
| `circuits/rwa-asset` | Asset issuance and compliance-gated transfer |
| `circuits/identity-zk` | Groth16 credential proofs |
| `arxd/node` | Block production, role selection, this chain's action type and dispatch |
| `arxd/network` | libp2p — gossip, discovery, block and state sync |
| `arxd/finality` | Precommit signing and aggregation to a finality record |
| `arxd/evidence` | Equivocation detection and slashing |

The boundary rule is a question, answered twice. **Does this need to know what
role the node is playing?** If yes it belongs under `arxd/`; if no it belongs
in `core/`. Role is decided once, at startup, as a config value — never as a
branch inside `execute_block` or the mempool. Each directory's `README.md`
covers its own half in detail.

Circuits never write. They validate a transition and return the proposed
changes; the node commits them, so a block's record and every account it
touched land in one atomic batch or not at all.

## Documentation

- [`docs/runbook.md`](docs/runbook.md) — operating a node: setup, health
  checks, stall detection, backups, upgrades, incident playbooks
- [`core/README.md`](core/README.md), [`arxd/README.md`](arxd/README.md),
  [`circuits/README.md`](circuits/README.md) — layer architecture and
  boundary rules
- [`scripts/README.md`](scripts/README.md) — development and operations tools
- [`monitoring/README.md`](monitoring/README.md) - native, external, and
  optional Docker monitoring paths

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
```

`examples/toy-chain` is a second chain built on the same `core` crates with a
different payload type and execution semantics — it exists to keep the generic
boundaries honest.

## License

Copyright 2026 Arxium Protocol AG. Licensed under the
[Apache License, Version 2.0](LICENSE).

Apache-2.0 is the mainstream choice for Rust layer-1 nodes (Solana, Sui) and
for the Cosmos stack. Beyond being permissive, it carries an explicit patent
grant and retaliation clause — which matters for a chain whose compliance and
identity circuits are aimed at institutional users, where a patent grant is
usually a prerequisite for participation.

Every crate in the workspace inherits `license = "Apache-2.0"` from
`[workspace.package]`, so the metadata Cargo reports and this file cannot
drift apart.
