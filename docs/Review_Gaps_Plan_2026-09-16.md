# Closing the external-review gaps — implementation plan (2026-09-16)

Four of the six items the external review raised are engineering; this is the
plan for them, in the order they depend on each other. The other two (forward
storage migrations, compliance-committee governance/attestation disputes/
slashing flows) are stated policy, not backlog — see `Arxium_OpenItems.md` §2
and `Reply_devnet_4_validators_2026-09-15.md` §5.

Every stage below is consensus-visible (state roots or block validity change),
so the whole set ships as one `reset-required` devnet bump: `SCHEMA_VERSION`
11 → 12, `WIRE_VERSION` 3 → 4.

## What the research says

- **Metering.** Substrate's model is the reference: a per-call *weight*
  (benchmarked execution cost on reference hardware), a per-block weight cap,
  and `fee = base + weight·rate + length·rate`. The one rule that matters for
  safety: a weight that *underestimates* cost is a DoS vector, so err high and
  cap the block. Ethereum's gas is the same idea with finer granularity;
  neither is needed at the action level Arxium has. Sources:
  [Substrate weights & fees](https://docs.substrate.io/build/tx-weights-fees/),
  [Shawn Tabrizi on weights](https://www.shawntabrizi.com/blog/substrate/substrate-weight-and-fees/).
- **Adjudication.** Arbitrum BoLD's lesson is that the honest party must always
  have a move and the dishonest party must eventually have none — which in
  practice means *every* step must be re-executable from proofs; a single
  unprovable step is a place a dishonest party can hide. Arxium's replay
  adjudicator already covers most action types; the gap is the three that read
  un-Merkleized state. Sources:
  [BoLD deep dive](https://docs.arbitrum.io/how-arbitrum-works/bold/bold-technical-deep-dive),
  [interactive fraud proofs](https://docs.arbitrum.io/how-arbitrum-works/interactive-fraud-proofs).
- **State proofs.** EIP-1186 (`eth_getProof`) is the shape everyone copies:
  value + Merkle path, and the client verifies against a header it trusts
  through consensus, not against anything the RPC says. Source:
  [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186).
- **Snapshot sync.** Cosmos SDK state sync: a manifest + hashed chunks; chunk
  hashes are only IO checksums, and the *only* trust is comparing the restored
  app hash against a header the light client verified from an operator-supplied
  `trust_height`/`trust_hash`. Snapshots are taken at fixed interval heights so
  a client can name one. Source:
  [Cosmos state sync guide](https://blog.cosmos.network/cosmos-sdk-state-sync-guide-99e4cf43be2f),
  [snapshots package](https://pkg.go.dev/cosmossdk.io/store/snapshots).

## Stage 1 — Proof-of-Execution resource metering

Today `ACTION_FEE` is flat, `fees_collected = applied.len() × fee`, and
`xc_poe::block_ep(...)` hashes `resources_used = 0`.

- `xc_runtime_api::ChainRuntime` gains `fn action_weight(&Action<P>) -> u64`
  and `fn action_fee_for(weight: u64) -> u128` (defaults: weight 1, flat fee —
  `toy-chain` needs nothing).
- CoreChain: `arxd/runtime/src/metering.rs` — a static weight table by
  `ActionPayload` variant plus a per-byte term on the encoded action. Units
  are nominal microseconds on the devnet reference host (`ponytail:` the
  table is hand-set; the upgrade path is a criterion-style benchmark that
  regenerates it). Fault-submission variants weigh what they cost: a full
  block replay. `fee = ACTION_FEE + weight × WEIGHT_FEE`.
- `ChainParams.max_block_weight` (genesis-fixed, in the root like the rest).
- `xc_executor::execute_actions` takes a `meter` closure and a budget, sums
  `weight_used`/`fees_collected` over *applied* actions, and stops at the cap:
  the remainder is returned as `deferred`. `produce_block` requeues deferred
  actions at the mempool front; `accept_block` rejects a block whose actions
  don't fit (`BlockOverWeight`) — an over-weight block is invalid, not
  partially applied.
- `charge_action_fee` charges the metered fee (so `fees_collected` and the
  sender debits agree by construction).
- `weight_used` is persisted per height (`meta:block_weight:{h}`, `CF_META`)
  and read by `arxd/finality` so the EP is `H(pre ‖ tx ‖ post ‖ weight)` on
  both producer and attester. It is *not* added to `Block` — that is a wire
  change every decoder would have to follow, and the value is already
  implied by the post-state root through the fees.
- RPC: `/action-fee` keeps its shape and adds `weight_fee`, `max_block_weight`;
  `/blocks/{h}` adds `weight_used`.

## Stage 2 — Complete proof-backed adjudication

`arxd/runtime/src/adjudicate.rs` resolves to `Disagreement` for
`AuthorizeOperator`, `RevokeOperator` (reverse operator index lives in
`CF_META`) and `LeaveValidator` (validator set passed as a bare slice, no proof
shape). Fault-submission variants stay unreplayable by construction.

- Merkleize the reverse operator index: `OperatorIndexKey` →
  `operator_index:{operator}` in `CF_GOVERNANCE`. `BlockView::apply_operator`
  overlays it in-block; the executor's operator lookups go through the view
  (so recording mode logs the keys a fraud proof needs).
- Make the validator-set snapshot height deterministic: the boundary hook
  writes `validator_set:{boundary+1}` at *every* boundary, including when it
  keeps the previous set. Then the set effective at `H` is at the key
  `validator_set:{epoch_of(H) × epoch_length}` (or `0`), which the adjudicator
  can read through a proof (`ValidatorSetKey`) using `ChainParams` (already in
  the root). `prune` stops deleting superseded `validator_set:` rows: they are
  Merkleized, and deleting the raw row while the trie keeps the leaf is what
  makes a raw-state export disagree with the certified root (Stage 4 needs
  raw == trie).
- Fix the latent root omission: `bls_keys` and `operator_updates` are
  Merkleized but were missing from the `state_root` preview overlay in
  `produce_block`/`accept_block` and from `inter_action_roots`, so a block
  carrying `RegisterBlsKey`/`AuthorizeOperator` signed a root that the
  committed trie did not equal. Add them to both.
- `state_entries` flattens `operator` and `operator_index`; `replay` and the
  block replay resolve `validators` from the proven snapshot and the operator
  index from the trie. Coverage becomes every non-fault-submission variant.

## Stage 3 — State-proof RPC

`ArxiumDb::prove`, `xc_poe::state_trie::verify_proof` and the compressed
`xc_artifact::StateProof` wire shape already exist; only the endpoint does not.

- `GET /accounts/{address}/proof`, `GET /accounts/{address}/assets/{ref}/proof`,
  `GET /validators/{address}/proof` — each returns
  `{ height, block_hash, state_root, key, key_hash, value, proof: StateProof,
  finality: FinalityRecord | null }` against the *finalized watermark* height,
  not the tip, so what the client verifies is a certified root. `value` is the
  decoded JSON alongside the raw bytes the proof commits to.
- Verification client-side: `verify_proof(state_root, proof)`, then check the
  block hash/root pair is the one named by the certificate. `arx-verify` gets
  a `state-proof` subcommand doing exactly that, so the check exists in one
  tool with no node.

## Stage 4 — Snapshot sync

Cosmos's shape, sized to what the node already has: state at height `H` is
reconstructible from current raw CFs by applying `meta:undo:{h}` records
descending from the tip to `H+1`, which is `revert_to`'s algorithm without the
write.

- Undo records are retained for `UNDO_RETAIN` heights below the watermark
  instead of being pruned the moment it passes, so a server can reconstruct
  any height in `[watermark − UNDO_RETAIN, tip]`.
- Wire (append-only): `SyncRequest::SnapshotManifest { height }` →
  `SyncResponse::SnapshotManifest(Option<SnapshotManifest>)` with
  `{ height, block_hash, state_root, entries, chunks, chunk_hashes }`;
  `SyncRequest::SnapshotChunk { height, index }` → `SyncResponse::SnapshotChunk
  { height, index, entries: Vec<(cf, key, value)> }`; the block and its
  certificate ride in the manifest. `WIRE_VERSION` 4.
- Server: `ArxiumDb::state_at(height)` under a RocksDB point-in-time snapshot;
  everything except `CF_BLOCKS`, `CF_MERKLE` and per-height/derived meta rows
  (`meta:undo:`, `meta:finality:`, `meta:precommit:`, `meta:roundcert:`,
  `meta:roundtimeout:`, `meta:dissent:`, `meta:tip_height`, `meta:merkle_root`,
  `meta:final_watermark`, `meta:schema_version`). Chunked at 4096 entries and
  cached per height for the duration of a sync. `ponytail:` the whole state is
  materialised in memory — fine at devnet scale; the upgrade path is a
  persisted per-interval checkpoint directory like Cosmos's.
- Client (`arxd --snapshot-trust-height H --snapshot-trust-hash 0x…`): only on
  a node whose tip is genesis. On the first peer `NodeInfo` with
  `finalized_height ≥ H`, fetch the manifest, check `block_hash == trust hash`
  and `block.state_root` matches, fetch chunks (checksum each), then
  `ArxiumDb::import_snapshot`: recompute the sparse-Merkle root of the imported
  state keys in memory (`xc_poe::state_trie::root_of`), require it to equal
  `block.state_root`, require the snapshot's genesis hash to equal the local
  one, verify the finality certificate against the snapshot's own validator set
  at `H`, and only then wipe the genesis state and write everything as one
  batch with tip/watermark/certificate at `H`. Normal `Blocks { from: H+1 }`
  sync takes over.
- Without a trust anchor nothing changes: replay from genesis, as today.

## Order and verification

1. Stage 1 (`cargo test -p arxd-runtime -p xc-executor -p arxd-node`, plus
   an over-weight block rejected / deferred round-trip test).
2. Stage 2 (`cargo test -p arxd-runtime` — new adjudication tests for the three
   previously-unresolvable variants resolving to `Culpable`).
3. Stage 3 (`cargo test -p xc-rpc` — a proof endpoint round-trips through
   `verify_proof`).
4. Stage 4 (`cargo test -p xc-storage -p arxd-network` — `root_of` equals the
   incremental trie root; `state_at(H)` equals the root block `H` signed;
   `import_snapshot` refuses a tampered entry).
5. `cargo clippy --workspace`, `cargo test --workspace`.
