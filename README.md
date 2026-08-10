# Arxium Protocol AG

# Arxium Network — Phase 1: Core Protocol

Single-validator (one-node) chain: accept signed `Action`s over RPC, order
them into blocks on a fixed schedule, apply them to account state. See
`core/README.md`, `arxd/README.md`, and `circuits/README.md` for the
architecture and the boundary rules between them.

## Done

- **Primitives** (`core/primitives`): `Action`/`ActionPayload`, `Block`
  (hashing, proposer signing + verification), bech32 `Address`,
  `Snapshot`/`AccountEntry`/`ValidatorEntry`, deterministic round-robin
  proposer selection (`expected_proposer`), ed25519 signature
  verification for actions.
- **Storage** (`core/storage`): `ArxiumDb`, a RocksDB wrapper with typed
  key encoding and a `BatchWritable` trait. Writes are atomic both
  single-item (`write_batch`) and multi-item (`write_batches`) — a block
  record and the account changes it caused commit together or not at all.
- **Mempool** (`core/mempool`): capacity-bounded, deduplicated by
  `(sender, nonce)`.
- **Account circuit** (`circuits/account`): validates nonce and balance
  for `ActionPayload::Transfer`, handles self-transfer correctly, returns
  proposed changes without writing them.
- **Executor** (`arxd/executor`): verifies action signatures, dispatches
  by payload type, chains same-block actions from one sender through an
  in-memory overlay, returns unwritten updates for the caller to commit
  atomically.
- **Node** (`arxd/node`): CLI, genesis bootstrap (embedded devnet JSON +
  cached snapshot), fixed-interval block production, round-robin
  validator turn-taking with block signing, tip-block signature
  verification on startup (rejects a corrupted/tampered tip instead of
  building on it), graceful shutdown (ctrl-c/SIGTERM finishes the current
  loop iteration before exiting), HTTP RPC (`POST /actions`,
  `GET /accounts/:address`, `GET /actions/:signature`, `GET /status` for
  chain name/tip height/tip hash) with constant-time bearer auth and per-IP
  rate limiting. `POST /actions` rejects a bad signature or a stale/replayed
  nonce (checked against on-chain state) before an action ever reaches the
  mempool — insufficient-balance is still only caught at block-production
  time, since balance can change before an action's turn.

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
