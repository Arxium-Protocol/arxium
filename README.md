# Arxium Network: A Layer 0 blockchain

## Phase 1: Core Protocol

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
way to talk to any other node. Before networking, `arxd/node/specs/devnet.json`
could declare two validators, but with no way for a second node to run and
sync, only one validator's parity of heights could ever be produced — the
chain advanced once and then stalled forever waiting on the other
validator's turn. That was fixed by the P2P/gossip and block/state sync
work below, live-verified past height 100 across two real machines. The
validator set was static at first too (read once from the genesis snapshot,
no join/leave mechanism) — that's now closed as well: join/leave is a
regular action, no separate governance path or `arxd/runtime` dependency
needed for it.

- **P2P/gossip layer** (done) — `arxd/network`, generic over the chain's
  payload type `P`. mDNS discovery on a LAN, `gossipsub` for action/block
  propagation, and a fixed-seed `--bootnode` identity plus a chain-spec-owned
  `Snapshot.boot_nodes` list (Polkadot-style) so a fresh node needs zero
  flags to find the network across separate machines/networks, not just a
  shared LAN. Nested under `arxd/` rather than `core/`, mirroring how
  Substrate/Polkadot keep `sc-network`/networking subsystems under
  `client/`/`node/` rather than in role-agnostic primitives.
- **Block/state sync** (done) — `libp2p::request_response` in `arxd/network`
  (`SyncRequest::Status`/`Blocks`, exchanged on connect and every 5s
  thereafter). A node behind a peer's reported tip requests the gap and
  applies each block through the same `accept_block` re-validation path
  gossip uses — no separate execution logic, sync is just a second delivery
  mechanism into the same acceptance path. Live-verified across two real
  machines converging to an identical tip height and hash after a late join.
- **Multi-validator round-robin that actually works** (done) — the devnet's
  two genesis validators both produce on their turn because both nodes are
  running, gossiping, and syncing, closing the stall described above.
  Verified live past height 100 across two machines.
- **Peer/network hardening** (done) — `connection_limits::Behaviour` caps
  established/pending connections per peer and overall; a per-peer
  bad-gossip counter (`arxd/network`'s `record_bad_gossip`) disconnects a
  peer sending unambiguously-bad gossip (undecodable bytes, forged action or
  block signatures) past a threshold, without penalizing an honest peer
  that's just behind (stale nonce, wrong turn, parent mismatch).
- **Dynamic validator set** (done) — `JoinValidator`/`LeaveValidator` are
  regular `ActionPayload` variants, going through the mempool and
  `execute_actions`/`accept_block` exactly like a transfer. A change applied
  in block `H` takes effect at block `H + 1` (a validator can't vote itself
  into that block's own proposer slot), and the set is stored per-height in
  `ArxiumDb` (`get_validator_set_at`) so a syncing/replaying node always
  computes the same round-robin proposer a live node did at the time.
  Leaving the last validator is rejected (would stall the chain forever).
  Stake is bookkeeping only — `expected_proposer` still ignores it.
- **`arxd/runtime` as a real crate** (not started) — currently just a
  placeholder README, not a workspace member. A state-root registry,
  cross-chain conflict resolution, and slashing — none of which the
  now-working dynamic validator set needed.

## Not started

- **Spoke Chains** (multi-chain phase) — vocabulary decided, nothing
  built. Free to rename before any code lands.
