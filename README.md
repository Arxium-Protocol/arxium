# Arxium Network: A Layer 0 blockchain

# Arxium Network — Phase 1: Core Protocol

Single-validator (one-node) chain: accept signed `Action`s over RPC, order
them into blocks on a fixed schedule, apply them to account state. See
`core/README.md`, `arxd/README.md`, and `circuits/README.md` for the
architecture and the boundary rules between them.

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
- **Hardening pass**: RPC/mempool mutex locks recover from poisoning
  instead of taking the whole node or RPC server down permanently after
  one panic; the rate limiter's per-IP map sweeps stale entries instead of
  growing forever; the validator signing key file is locked to `0600` on
  every load, not just on first generation; block/account commits fsync
  (`WriteOptions::set_sync(true)`) so the on-disk tip can't outrun durable
  data across a hard crash.

Phase 1 has no remaining gaps of its own — the in-memory mempool isn't one:
losing pending actions on restart is standard (Bitcoin/Ethereum included),
and the intended recovery path is peer re-broadcast, not disk persistence.
That makes it a Phase 2/networking capability, not something to fix here.

## Phase 2: Networking & Multi-Validator

Every item below traces back to the same root gap: a single node with no
way to talk to any other node. No P2P, no gossip, no block/state sync — so
the validator set is necessarily static (read once from the genesis
snapshot, no join/leave mechanism, and none would propagate even if there
were), and `arxd/runtime` (validator-set management, state-root registry,
conflict resolution, slashing) isn't a real crate yet, since none of that
means anything without a network to enforce it over. Concretely today:
`arxd/node/specs/devnet.json` already declares two validators, but with no
way for a second node to run and sync, only one validator's parity of
heights can ever be produced — the chain advances once and then stalls
forever waiting on the other validator's turn. That's not a bug to patch
around; it's what "no networking" actually means once there's more than
one validator.

- **P2P/gossip layer** — block and action propagation between nodes.
  Prerequisite for every other item below. Also what makes mempool loss on
  restart a non-issue: a node re-syncs pending actions from peers instead
  of needing its own mempool on disk.
- **Block/state sync** — a node that joins late (or restarts far behind)
  catches up from peers instead of only ever trusting its own local
  RocksDB.
- **Multi-validator round-robin that actually works** — the devnet's two
  genesis validators both produce on their turn because both nodes are
  running and syncing, closing the stall described above.
- **`arxd/runtime` as a real crate** — validator-set management (join/leave
  propagated over the network), a state-root registry, conflict
  resolution, and slashing.
- **Dynamic validator set** — join/leave against `arxd/runtime`, no longer
  fixed at genesis.
- **Explorer frontend** — `core/rpc` already serves the range/list/search
  endpoints (`GET /blocks`, `GET /accounts/:address/actions`,
  `GET /search`, …) an explorer needs; the UI consuming them hasn't been
  built. Not networking-blocked itself, but a multi-node chain is what
  makes an explorer worth having.

## Not started

- **Spoke Chains** (multi-chain phase) — vocabulary decided, nothing
  built. Free to rename before any code lands.
