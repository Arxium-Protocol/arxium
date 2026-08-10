# Arxium Protocol AG

# Arxium Network — Phase 1: Core Protocol

Single-validator (one-node) chain: accept signed `Action`s over RPC, order
them into blocks on a fixed schedule, apply them to account state. See
`core/README.md`, `arxd/README.md`, and `circuits/README.md` for the
architecture and the boundary rules between them.

## Done

- **Primitives** (`core/primitives`): `Action<P>`/`Block<P>`, generic over
  a chain-specific payload type `P` (hashing, proposer signing +
  verification), bech32 `Address`, `Snapshot`/`AccountEntry`/
  `ValidatorEntry`, deterministic round-robin proposer selection
  (`expected_proposer`), ed25519 signature verification for actions. Each
  chain defines its own payload enum (e.g. `arxd/node`'s `ActionPayload`,
  `examples/toy-chain`'s `RwaPayload`) — there is no shared payload type.
- **Storage** (`core/storage`): `ArxiumDb`, a RocksDB wrapper with typed
  key encoding and a `BatchWritable` trait. Writes are atomic both
  single-item (`write_batch`) and multi-item (`write_batches`) — a block
  record and the account changes it caused commit together or not at all.
  `AccountUpdates` (the write-batch shape account-touching circuits hand
  back) lives here so any circuit can produce it without depending on
  another circuit crate.
- **Mempool** (`core/mempool`): `Mempool<P>`, capacity-bounded,
  deduplicated by `(sender, nonce)`.
- **Account circuit** (`circuits/account`): validates nonce and balance
  for a plain sender/nonce/to/amount transfer (no `Action`/payload
  knowledge), handles self-transfer correctly, returns proposed changes
  without writing them.
- **RWA asset circuit** (`circuits/rwa-asset`): `apply_issue` (self-mint
  by the designated issuer) and `apply_compliant_transfer` (transfer
  gated on both sender and recipient being KYC'd/allowlisted, via
  `AccountEntry.identity_hash`) — composes with `circuits/account` for
  the actual balance/nonce math rather than reimplementing it.
- **Executor** (`core/executor`): verifies action signatures, dispatches
  each action through a caller-supplied `dispatch` closure (payload →
  circuit call is chain-specific, not hardcoded here), chains same-block
  actions from one sender through an in-memory overlay, returns unwritten
  updates for the caller to commit atomically. Chain-agnostic —
  `examples/toy-chain` uses it with its own payload type and dispatch
  table, proving the generic design holds for a chain with different
  execution semantics than CoreChain's.
- **CLI** (`core/cli`): the shared `--base-path`/`--port`/`--validator`/
  `--rpc-token`/`--rpc-bind` arg struct → `NodeConfig`. Generic
  node-operator config, no chain-specific flags — moved out of `arxd/node`
  once nothing about it turned out to need CoreChain knowledge.
- **Genesis** (`core/genesis`): `load_or_init_snapshot` — cache-or-parse
  mechanics for a chain's genesis `Snapshot` (bincode cache after first
  JSON parse). Takes the embedded genesis JSON as a parameter; each chain
  still owns its own JSON file (e.g. `arxd/node/specs/devnet.json`).
- **RPC** (`core/rpc`): `spawn_http_ingest<P>`, generic over the chain's
  payload type. HTTP ingest (`POST /actions`, `GET /accounts/:address`,
  `GET /actions/:signature`, `GET /status` for chain name/tip height/tip
  hash) with constant-time bearer auth and per-IP rate limiting.
  `POST /actions` rejects a bad signature or a stale/replayed nonce
  (checked against on-chain state) before an action ever reaches the
  mempool — insufficient-balance is still only caught at block-production
  time, since balance can change before an action's turn. Explorer-ready
  reads: `GET /blocks` (bounded range), `GET /blocks/:height`,
  `GET /blocks/by-hash/:hash`, `GET /accounts/:address/actions`
  (paginated, newest-first history), and `GET /search` (height/address/hash,
  one endpoint so a client doesn't need to guess input type).
- **Node** (`arxd/node`): wires the above together for CoreChain —
  fixed-interval block production, round-robin validator turn-taking with
  block signing, tip-block signature verification on startup (rejects a
  corrupted/tampered tip instead of building on it), graceful shutdown
  (ctrl-c/SIGTERM finishes the current loop iteration before exiting),
  and CoreChain's own `ActionPayload`/dispatch table.

## Missing for Phase 1

- **No networking** — this is a single-node chain. No P2P, no gossip, no
  block/state sync between nodes.
- **Static validator set** — read once from the genesis snapshot; no
  join/leave mechanism, and none would propagate without networking
  anyway.
- **`arxd/runtime` isn't a real crate yet** — validator-set management,
  state-root registry, conflict resolution, and slashing are all
  unbuilt; today's `Snapshot` has no commitment to post-transfer state.
- **In-memory mempool** — pending actions do not survive a restart.

## Not started

- **Spoke Chains** (multi-chain phase) — vocabulary decided, nothing
  built. Free to rename before any code lands.
