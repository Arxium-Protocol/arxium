// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The record types that get written to RocksDB, and their
//! [`BatchWritable`](super::BatchWritable) impls — one per column-family
//! record shape. Split out of `lib.rs` because they are a flat, uniform list
//! that only grows: each new record type adds a struct and an encode impl and
//! interacts with nothing else in the crate.

use super::*;

/// Seeds `GenesisHashKey` with this chain's genesis hash (block 0's state
/// root). Written once by `arxd/genesis` after the root is known — it cannot
/// be part of the genesis snapshot batch itself, since the root is computed
/// from that batch.
pub struct GenesisHash(pub String);

impl BatchWritable for GenesisHash {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        Ok(vec![(
            GenesisHashKey.encode(),
            bincode::serde::encode_to_vec(&self.0, config)?,
        )])
    }
}

impl BatchWritable for Snapshot {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = vec![
            (b"meta:height".to_vec(), self.height.to_be_bytes().to_vec()),
            (
                b"meta:chain_name".to_vec(),
                self.chain_name.as_bytes().to_vec(),
            ),
        ];
        for (address, account) in &self.accounts {
            let key = AccountKey(address).encode();
            let value = bincode::serde::encode_to_vec(account, config)?;
            entries.push((key, value));
        }
        for (address, validator) in &self.validators {
            let key = format!("validator:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(validator, config)?;
            entries.push((key, value));

            // ponytail: genesis's `validator.stake` was cosmetic-only — no
            // StakeAllocation was ever materialized, so genesis validators
            // could never be slashed (equivocation silently no-oped) or
            // leave (`stake_lookup` found nothing). Write the same
            // self-stake shape `circuit_staking::apply_stake` would.
            let allocation = StakeAllocation {
                master: address.clone(),
                validator: address.clone(),
                active_amount: validator.stake,
                unbonding: None,
                created_at: self.height,
                updated_at: self.height,
            };
            entries.push((
                StakeKey {
                    master: address,
                    validator: address,
                }
                .encode(),
                bincode::serde::encode_to_vec(&allocation, config)?,
            ));
            entries.push((
                StakeByValidatorKey(address).encode(),
                bincode::serde::encode_to_vec(vec![address.clone()], config)?,
            ));

            // The other half of the same fix: `apply_stake` always moves the
            // staked amount into `stake_subaccount(validator)`'s real
            // balance, so every allocation it creates is backed by funds a
            // slash/unbond can actually debit. The synthesized allocation
            // above skipped that, leaving the sub-account at its default
            // zero balance — `circuit_staking::apply_slash` would then
            // underflow subtracting from it (hit for real via downtime
            // slashing, which is the first path that reaches a genesis-only
            // validator without needing submitted evidence). Fund it here so
            // genesis produces the same invariant `apply_stake` would:
            // sub-account balance >= sum of active allocations against it.
            let sub_account = stake_subaccount(address);
            let mut sub_entry = self
                .accounts
                .get(&sub_account)
                .cloned()
                .unwrap_or(AccountEntry {
                    balance: 0,
                    ..Default::default()
                });
            sub_entry.balance += validator.stake;
            entries.push((
                AccountKey(&sub_account).encode(),
                bincode::serde::encode_to_vec(&sub_entry, config)?,
            ));
        }
        // Genesis set: powers from the spec's stakes, same rule the boundary
        // hook applies later; every genesis validator starts `Active`.
        let genesis_stakes: BTreeMap<Address, u128> = self
            .validators
            .iter()
            .map(|(a, v)| (a.clone(), v.stake))
            .collect();
        entries.push((
            b"validator_set:00000000000000000000".to_vec(),
            bincode::serde::encode_to_vec(assign_voting_power(&genesis_stakes), config)?,
        ));
        for address in self.validators.keys() {
            entries.push((
                ValidatorStatusKey(address).encode(),
                bincode::serde::encode_to_vec(&ValidatorStatus::Active, config)?,
            ));
        }
        entries.push((
            ChainParamsKey.encode(),
            bincode::serde::encode_to_vec(&self.params, config)?,
        ));
        if let Some(attestor) = &self.attestor {
            // Seeds the multi-attestor registry with this chain-spec's
            // legacy single attestor field, so a spec written before the
            // Trust Spectrum registry existed still grants a working
            // attestor at genesis instead of silently having none.
            let record = AttestorRecord {
                name: "genesis".to_string(),
                registered_at: self.height,
            };
            entries.push((
                AttestorRecordKey(attestor).encode(),
                bincode::serde::encode_to_vec(&record, config)?,
            ));
        }
        for (role, admin) in [
            (AdminRole::Attestor, &self.attestor_admin),
            (AdminRole::Freeze, &self.freeze_admin),
            (AdminRole::Recovery, &self.recovery_admin),
        ] {
            if let Some(admin) = admin {
                entries.push((
                    AdminKey(role).encode(),
                    bincode::serde::encode_to_vec(admin, config)?,
                ));
            }
        }
        Ok(entries)
    }
}

/// The stake-weighted validator set effective starting `effective_height`,
/// written by the epoch-boundary hook (through `xc_executor::accept_block`/
/// `produce_block`) at the last block of each epoch — one full-set snapshot
/// per epoch, looked up via `ArxiumDb::get_validator_set_at`.
/// `effective_height` is the boundary height + 1, the first block of the
/// next epoch: a set can never affect the block that introduced it.
pub struct ValidatorSetSnapshot {
    pub effective_height: u64,
    pub validators: BTreeMap<Address, VotingPower>,
}

impl ValidatorSetSnapshot {
    /// A set where every listed validator holds equal stake — what a fresh
    /// genesis of equally-funded validators produces. Mostly for tests and
    /// tooling that only care about membership.
    pub fn equal_power(effective_height: u64, validators: &[Address]) -> Self {
        let stakes: BTreeMap<Address, u128> = validators.iter().map(|a| (a.clone(), 1)).collect();
        Self {
            effective_height,
            validators: assign_voting_power(&stakes),
        }
    }
}

impl BatchWritable for ValidatorSetSnapshot {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        // BTreeMap encodes in key order, so the bytes are a pure function
        // of the set — the same property the old sorted Vec had.
        Ok(vec![(
            ValidatorSetKey(self.effective_height).encode(),
            bincode::serde::encode_to_vec(&self.validators, config)?,
        )])
    }
}

/// Writes the genesis-fixed consensus parameters row — what
/// `Snapshot::batch_entries` seeds; exposed for tooling and tests that build
/// a chain without a full genesis.
pub struct ChainParamsRow(pub ChainParams);

impl BatchWritable for ChainParamsRow {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        Ok(vec![(
            ChainParamsKey.encode(),
            bincode::serde::encode_to_vec(&self.0, bincode::config::standard())?,
        )])
    }
}

/// Validator status rows touched by a block, keyed by validator; `None`
/// deletes the row (a validator that has fully left).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStatusUpdates(pub BTreeMap<Address, Option<ValidatorStatus>>);

impl BatchWritable for ValidatorStatusUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        self.0
            .iter()
            .filter_map(|(address, status)| status.as_ref().map(|s| (address, s)))
            .map(|(address, status)| {
                Ok((
                    ValidatorStatusKey(address).encode(),
                    bincode::serde::encode_to_vec(status, config)?,
                ))
            })
            .collect()
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(self
            .0
            .iter()
            .filter(|(_, s)| s.is_none())
            .map(|(a, _)| ValidatorStatusKey(a).encode())
            .collect())
    }
}

impl<P: Serialize> BatchWritable for Block<P> {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();

        let block_key = format!("block:{:020}", self.height).into_bytes();
        let block_value = bincode::serde::encode_to_vec(self, config)?;

        let mut entries = vec![
            (block_key, block_value),
            (
                b"meta:tip_height".to_vec(),
                self.height.to_be_bytes().to_vec(),
            ),
            (
                format!("block_hash:{}", self.hash()).into_bytes(),
                self.height.to_be_bytes().to_vec(),
            ),
        ];

        for action in self.actions.iter() {
            if let Some(signature) = &action.signature {
                entries.push((
                    format!("action:{}", signature).into_bytes(),
                    self.height.to_be_bytes().to_vec(),
                ));
            }
        }

        Ok(entries)
    }
}

/// Marks equivocation evidence against `proposer` at `height` as processed,
/// so `ArxiumDb::evidence_processed` can reject a resubmission. Written
/// alongside the slash's `AccountUpdates`/`StakeUpdates` in the same atomic
/// batch — see `evidence_processed`.
#[derive(Debug)]
pub struct EvidenceMarker {
    pub height: u64,
    pub proposer: Address,
}

impl BatchWritable for EvidenceMarker {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = EvidenceMarkerKey {
            height: self.height,
            proposer: &self.proposer,
        }
        .encode();
        Ok(vec![(key, vec![1u8])])
    }
}

/// Registers `address`'s BLS pubkey so `arxd/finality` can verify precommit
/// votes and the resulting aggregate signature against it. Kept separate
/// from `Address` (an Ed25519-derived bech32 identity) rather than folded
/// in — BLS pubkeys are a different byte length and only meaningful once/if
/// the address is in the validator set, not an identity of their own.
///
/// `effective_height` is the height this key becomes valid *from* — a
/// `RegisterBlsKey` action executed in block `H` takes effect at `H + 1`,
/// same one-block delay as `ValidatorSetSnapshot`, so a block never observes
/// a key change caused by its own actions. Genesis registrations use `0`.
/// Written alongside the plain current-key record so `get_bls_pubkey_at` can
/// recover which key was valid at any past height even after a rotation.
///
/// `previous_pubkey` is the address's prior current key, if any (`None` at
/// genesis or first registration) — carried here so the reverse
/// `BlsPubkeyOwnerKey` index can be deleted for the old pubkey at the same
/// time the new one is written, freeing it for reuse exactly like the linear
/// scan `bls_pubkey_owner` used to do implicitly.
#[derive(Debug)]
pub struct BlsKeyRegistration {
    pub address: Address,
    pub pubkey: BlsPublicKey,
    pub effective_height: u64,
    pub previous_pubkey: Option<BlsPublicKey>,
}

impl BatchWritable for BlsKeyRegistration {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self.pubkey, config)?;
        let current_key = BlsKeyKey(&self.address).encode();
        let history_key = format!(
            "meta:blskey_hist:{}:{:020}",
            self.address, self.effective_height
        )
        .into_bytes();
        let owner_key = BlsPubkeyOwnerKey(&self.pubkey).encode();
        let owner_value = bincode::serde::encode_to_vec(&self.address, config)?;
        Ok(vec![
            (current_key, value.clone()),
            (history_key, value),
            (owner_key, owner_value),
        ])
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        match &self.previous_pubkey {
            Some(previous) if previous != &self.pubkey => {
                Ok(vec![BlsPubkeyOwnerKey(previous).encode()])
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// Grants or revokes authorization for an operator to submit
/// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey` on one or more
/// validators' behalf (see `arxd/node`'s `AuthorizeOperator`/
/// `RevokeOperator`), plus the full updated reverse-index list for every
/// operator whose list changed as a result — same "caller computes the full
/// new value via a lookup closure, storage just writes it, `None`/empty
/// means delete" shape as `StakeUpdates`.
#[derive(Debug, Default)]
pub struct OperatorUpdates {
    /// `validator -> Some(operator)` to authorize, `validator -> None` to revoke.
    pub authorization: std::collections::BTreeMap<Address, Option<Address>>,
    /// `operator -> full new validator list` (empty means delete).
    pub operator_index: std::collections::BTreeMap<Address, Vec<Address>>,
}

impl BatchWritable for OperatorUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (validator, operator) in &self.authorization {
            if let Some(operator) = operator {
                let key = OperatorKey(validator).encode();
                let value = bincode::serde::encode_to_vec(operator, config)?;
                entries.push((key, value));
            }
        }
        for (operator, validators) in &self.operator_index {
            if !validators.is_empty() {
                let value = bincode::serde::encode_to_vec(validators, config)?;
                entries.push((OperatorIndexKey(operator).encode(), value));
            }
        }
        Ok(entries)
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut deletes = Vec::new();
        for (validator, operator) in &self.authorization {
            if operator.is_none() {
                deletes.push(OperatorKey(validator).encode());
            }
        }
        for (operator, validators) in &self.operator_index {
            if validators.is_empty() {
                deletes.push(OperatorIndexKey(operator).encode());
            }
        }
        Ok(deletes)
    }
}

/// Everything block `height` changed, as one readable record: the same
/// rows the block's write batch carries, flattened to JSON-friendly lists
/// (tuple map keys don't serialize) plus the producer's `dropped` list.
/// `CF_META` — an index over state, not state, so it never moves the root
/// and an old DB without it still opens; it simply answers 404 for blocks
/// written before it existed. Consumed by `GET /blocks/{height}/effects`,
/// which is what lets an indexer keep account/holder/validator state
/// without re-executing the runtime.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockEffects {
    pub height: u64,
    pub accounts: BTreeMap<Address, AccountEntry>,
    pub asset_balances: Vec<AssetBalanceEffect>,
    pub holder_states: Vec<HolderStateEffect>,
    pub stakes: Vec<StakeEffect>,
    pub validator_statuses: BTreeMap<Address, Option<ValidatorStatus>>,
    /// Set only at an epoch boundary: the set effective from `height + 1`.
    pub validator_set: Option<BTreeMap<Address, VotingPower>>,
    pub asset_registrations: Vec<Asset>,
    /// Every action the producer tried and rejected while building this
    /// block. Only the producing node knows these; every other node stores
    /// an empty list here.
    pub dropped: Vec<DroppedAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetBalanceEffect {
    pub asset: AssetRef,
    pub owner: Address,
    pub balance: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderStateEffect {
    pub asset: AssetRef,
    pub holder: Address,
    pub state: HolderState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEffect {
    pub master: Address,
    pub validator: Address,
    /// `None` = allocation removed (fully resolved or slashed).
    pub allocation: Option<StakeAllocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedAction {
    pub signature: String,
    /// Carried because a dropped action never reaches a block, so nothing
    /// else records who sent it — and "my failed actions" is the query.
    pub sender: Address,
    pub reason: String,
}

impl BlockEffects {
    /// Builds the record from the update sets a block is about to commit —
    /// one call site each in `accept_block` and `produce_block`, so the two
    /// can't drift on what counts as an effect.
    // ponytail: operators, BLS keys, evidence and attestors are not here; add
    // them when an indexer needs them.
    #[allow(clippy::too_many_arguments)]
    pub fn collect(
        height: u64,
        accounts: &AccountUpdates,
        stakes: &StakeUpdates,
        assets: &AssetBalanceUpdates,
        holder_states: &HolderStateUpdates,
        validator_statuses: &ValidatorStatusUpdates,
        validator_set: Option<&BTreeMap<Address, VotingPower>>,
        asset_registrations: &[Asset],
        dropped: &[DroppedAction],
    ) -> Self {
        Self {
            height,
            accounts: accounts.0.clone(),
            asset_balances: assets
                .0
                .iter()
                .map(|((asset, owner), balance)| AssetBalanceEffect {
                    asset: asset.clone(),
                    owner: owner.clone(),
                    balance: *balance,
                })
                .collect(),
            holder_states: holder_states
                .0
                .iter()
                .map(|((asset, holder), state)| HolderStateEffect {
                    asset: asset.clone(),
                    holder: holder.clone(),
                    state: state.clone(),
                })
                .collect(),
            stakes: stakes
                .allocations
                .iter()
                .map(|((master, validator), allocation)| StakeEffect {
                    master: master.clone(),
                    validator: validator.clone(),
                    allocation: allocation.clone(),
                })
                .collect(),
            validator_statuses: validator_statuses.0.clone(),
            validator_set: validator_set.cloned(),
            asset_registrations: asset_registrations.to_vec(),
            dropped: dropped.to_vec(),
        }
    }
}

pub(crate) fn block_effects_key(height: u64) -> Vec<u8> {
    format!("meta:block_effects:{height:020}").into_bytes()
}

impl BatchWritable for BlockEffects {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let value = bincode::serde::encode_to_vec(self, bincode::config::standard())?;
        Ok(vec![(block_effects_key(self.height), value)])
    }
}

/// `weight_used` of block `height` (`xc_executor::ExecutionOutcome`), kept
/// beside the block so an attester can hash the same PoE `resources_used`
/// the producer did (`xc_poe::block_ep`) without re-executing. `CF_META`:
/// it is implied by the state root already (fees are a function of weight),
/// so it must not move the root a second time.
#[derive(Debug, Clone, Copy)]
pub struct BlockWeight {
    pub height: u64,
    pub weight_used: u64,
}

pub(crate) fn block_weight_key(height: u64) -> Vec<u8> {
    format!("meta:block_weight:{height:020}").into_bytes()
}

impl BatchWritable for BlockWeight {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        Ok(vec![(
            block_weight_key(self.height),
            self.weight_used.to_le_bytes().to_vec(),
        )])
    }
}

/// A block finality certificate: proof 2/3+ of `height`'s validator set
/// independently BLS-signed `block_hash`. Stored as its own record rather
/// than a `Block<P>` field — it's produced in a second round after the
/// block already propagated, so embedding it would mean mutating an
/// already-gossiped/stored block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityRecord {
    pub height: u64,
    pub block_hash: Hash32,
    pub signers: Vec<Address>,
    pub aggregate_signature: BlsSignature,
    /// The execution-proof commitment every signer signed over, alongside
    /// `height`/`block_hash` (see `arxd_finality::precommit_signing_bytes`).
    /// Carried here because without it a node that did not tally these votes
    /// itself cannot reconstruct the signed message, and so cannot check the
    /// aggregate — which is exactly what a peer must do before it will
    /// consider rolling its own chain back. It needs no independent trust:
    /// a wrong `ep` simply fails the aggregate check.
    pub ep: [u8; 32],
}

/// One validator's persisted precommit vote for `height`/`block_hash`, so a
/// restart before quorum is reached doesn't lose a tally `arxd/finality`
/// already gossiped and verified. Deleted once its height finalizes
/// (superseded by `FinalityRecord`) or ages out of `TALLY_RETENTION_HEIGHTS`,
/// mirroring the in-memory tally's own lifetime exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecommitVoteRecord {
    pub height: u64,
    pub block_hash: Hash32,
    pub voter: Address,
    pub signature: BlsSignature,
    pub ep: [u8; 32],
}

impl BatchWritable for PrecommitVoteRecord {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = format!(
            "meta:precommit:{:020}:{}:{}",
            self.height, self.block_hash, self.voter
        )
        .into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One validator's persisted dissent for `height` — mirrors
/// `PrecommitVoteRecord` exactly, including the `TALLY_RETENTION_HEIGHTS`
/// pruning schedule; see `arxd_finality::Dissent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissentRecord {
    pub height: u64,
    pub block_hash: Hash32,
    pub state_root: String,
    pub ep: [u8; 32],
    pub reason: String,
    pub voter: Address,
    pub signature: BlsSignature,
    /// `sha256(signing_bytes_for(disputed block's header))` — binds this
    /// dissent to the exact block it disagrees with, since `block_hash` is
    /// an opaque chain-internal hash a verifier holding only this record
    /// cannot recompute. See `arxd_finality::Dissent::header_commitment`.
    pub header_commitment: [u8; 32],
}

impl BatchWritable for DissentRecord {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = format!("meta:dissent:{:020}:{}", self.height, self.voter).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

impl BatchWritable for FinalityRecord {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = format!("meta:finality:{:020}", self.height).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

// The type itself now lives in `xc_primitives` (so `Block::round_certificate`
// can carry it — `core/primitives` can't depend on `core/storage`). Re-
// exported under its old name here so existing `use xc_storage::
// RoundCertificate` call sites (`arxd/finality`) don't need to change.
pub use xc_primitives::RoundCertificate;

impl BatchWritable for RoundCertificate {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = format!("meta:roundcert:{:020}:{}", self.height, self.round).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One validator's persisted vote that `round` at `height` timed out —
/// mirrors `PrecommitVoteRecord` exactly, including the
/// `TALLY_RETENTION_HEIGHTS`-driven pruning; see
/// `arxd_finality::RoundTimeoutVote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundTimeoutVoteRecord {
    pub height: u64,
    pub round: u32,
    pub voter: Address,
    pub signature: BlsSignature,
}

impl BatchWritable for RoundTimeoutVoteRecord {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let key = format!(
            "meta:roundtimeout:{:020}:{}:{}",
            self.height, self.round, self.voter
        )
        .into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// A set of account changes to be written atomically. Not account-circuit
/// business logic — just the write-batch shape any circuit that touches
/// accounts (`circuit-account`, `circuit-rwa-asset`, ...) hands back.
#[derive(Debug, Default)]
pub struct AccountUpdates(pub BTreeMap<Address, AccountEntry>);

impl BatchWritable for AccountUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (address, entry) in &self.0 {
            let key = AccountKey(address).encode();
            let value = bincode::serde::encode_to_vec(entry, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

/// A set of stake-allocation changes to be written atomically alongside a
/// block, same reasoning as `AccountUpdates`. `allocations` maps
/// `(master, validator) -> Some(allocation)` for an upsert or `None` for a
/// removal (fully slashed / fully resolved). `validator_index` maps
/// `validator -> full new master list` for that validator's
/// `stake_by_validator:` row — an empty list removes the row.
#[derive(Debug, Default)]
pub struct StakeUpdates {
    pub allocations: std::collections::BTreeMap<(Address, Address), Option<StakeAllocation>>,
    pub validator_index: std::collections::BTreeMap<Address, Vec<Address>>,
}

impl BatchWritable for StakeUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for ((master, validator), allocation) in &self.allocations {
            if let Some(allocation) = allocation {
                let key = StakeKey { master, validator }.encode();
                let value = bincode::serde::encode_to_vec(allocation, config)?;
                entries.push((key, value));
            }
        }
        for (validator, masters) in &self.validator_index {
            if !masters.is_empty() {
                let key = StakeByValidatorKey(validator).encode();
                let value = bincode::serde::encode_to_vec(masters, config)?;
                entries.push((key, value));
            }
        }
        Ok(entries)
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut deletes = Vec::new();
        for ((master, validator), allocation) in &self.allocations {
            if allocation.is_none() {
                deletes.push(StakeKey { master, validator }.encode());
            }
        }
        for (validator, masters) in &self.validator_index {
            if masters.is_empty() {
                deletes.push(StakeByValidatorKey(validator).encode());
            }
        }
        Ok(deletes)
    }
}

/// A set of asset-balance changes to be written atomically alongside a
/// block, same reasoning as `AccountUpdates` — mint (`RegisterAsset`'s
/// `IssueAsset`) and compliance-gated transfer both produce one of these
/// rather than touching `AccountUpdates`, which is what keeps regulated
/// asset balances out of the native token balance.
#[derive(Debug, Default)]
pub struct AssetBalanceUpdates(pub BTreeMap<(AssetRef, Address), u128>);

impl BatchWritable for AssetBalanceUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for ((asset, owner), balance) in &self.0 {
            let key = AssetBalanceKey { asset, owner }.encode();
            let value = bincode::serde::encode_to_vec(balance, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

/// The non-consensus index rows that make asset state readable by wallet:
/// the registry list behind `GET /assets`, and one list per owner behind
/// `GET /accounts/{address}/assets`.
///
/// Both live in `CF_META`, which `is_state_key` excludes, so writing them
/// leaves the state root untouched — a node that somehow lost these rows
/// would serve worse listings but would still agree on consensus. That is
/// the whole reason this is an index rather than a re-keying of
/// `AssetBalanceKey`, whose keys are merkleized.
///
/// Only changed rows are present; a block with no asset activity produces an
/// empty value here and writes nothing.
#[derive(Debug, Default)]
pub struct AssetIndexUpdates {
    /// The full new registered-asset-ref list, when a `RegisterAsset` in this
    /// block added to it.
    pub registry: Option<Vec<AssetRef>>,
    /// `owner -> full new list of asset refs held`.
    pub owners: BTreeMap<Address, Vec<AssetRef>>,
    /// `asset_ref -> full new list of holders with a non-zero balance`.
    pub holders: BTreeMap<AssetRef, Vec<Address>>,
}

impl AssetIndexUpdates {
    /// Whether anything would be written. Lets a caller skip pushing this
    /// into the batch at all on the common no-asset-activity block.
    pub fn is_empty(&self) -> bool {
        self.registry.is_none() && self.owners.is_empty() && self.holders.is_empty()
    }
}

impl BatchWritable for AssetIndexUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        if let Some(ids) = &self.registry {
            let value = bincode::serde::encode_to_vec(ids, config)?;
            entries.push((AssetIndexKey.encode(), value));
        }
        for (owner, refs) in &self.owners {
            let value = bincode::serde::encode_to_vec(refs, config)?;
            entries.push((AccountAssetsKey(owner).encode(), value));
        }
        for (asset, holders) in &self.holders {
            let value = bincode::serde::encode_to_vec(holders, config)?;
            entries.push((AssetHoldersKey(asset).encode(), value));
        }
        Ok(entries)
    }
}

/// `(asset_ref, holder) -> new HolderState`, the issuer's per-holder freeze
/// controls. `CF_ASSETS`, so part of the state root like the balances.
#[derive(Debug, Default, Clone)]
pub struct HolderStateUpdates(pub BTreeMap<(AssetRef, Address), HolderState>);

impl BatchWritable for HolderStateUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for ((asset, holder), state) in &self.0 {
            let key = AssetHolderStateKey { asset, holder }.encode();
            let value = bincode::serde::encode_to_vec(state, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

impl BatchWritable for Asset {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let key = AssetKey(&self.asset_ref).encode();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One `RegisterAttestor` write — a single `CF_ATTESTORS` record, merkleized
/// via `is_state_key` (unlike `Asset`'s `CF_META` registry row).
#[derive(Debug)]
pub struct AttestorRegistration {
    pub attestor: Address,
    pub record: AttestorRecord,
}

impl BatchWritable for AttestorRegistration {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        let config = bincode::config::standard();
        let key = AttestorRecordKey(&self.attestor).encode();
        let value = bincode::serde::encode_to_vec(&self.record, config)?;
        Ok(vec![(key, value)])
    }
}

/// One `DeregisterAttestor` write — physically removes the `CF_ATTESTORS`
/// record rather than flagging it inactive, same as any other merkleized
/// state key; deletions are already routed through the state root via
/// `batch_deletes`.
#[derive(Debug)]
pub struct AttestorDeregistration(pub Address);

impl BatchWritable for AttestorDeregistration {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        Ok(Vec::new())
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(vec![AttestorRecordKey(&self.0).encode()])
    }
}

/// Raw `CF_GOVERNANCE` rows an action wrote — `Some` puts, `None` deletes,
/// already bincode-encoded by whoever built them (the governance circuit
/// encodes via `KeySpec`, so the shape is still typed at the source). One
/// generic carrier rather than a `BlockUpdates` field per row kind because
/// executing a proposal can touch proposals, votes, `chain_params` and
/// `admin:*` in one action, and every new field costs a pass through the
/// executor, producer, adjudicator and effects log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GovernanceUpdates(pub BTreeMap<Vec<u8>, Option<Vec<u8>>>);

impl GovernanceUpdates {
    pub fn put<K: KeySpec>(&mut self, key: &K, value: &K::Value) -> Result<(), StorageError> {
        debug_assert_eq!(K::CF, CF_GOVERNANCE);
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
        self.0.insert(key.encode(), Some(bytes));
        Ok(())
    }

    pub fn delete<K: KeySpec>(&mut self, key: &K) {
        debug_assert_eq!(K::CF, CF_GOVERNANCE);
        self.0.insert(key.encode(), None);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn extend(&mut self, other: GovernanceUpdates) {
        self.0.extend(other.0);
    }
}

impl BatchWritable for GovernanceUpdates {
    fn batch_entries(&self) -> Result<BatchEntries, StorageError> {
        Ok(self
            .0
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| (k.clone(), v.clone())))
            .collect())
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(self
            .0
            .iter()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.clone())
            .collect())
    }
}
