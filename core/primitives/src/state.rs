// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Every raw `u128` amount/balance/stake field on this page is denominated in
// IUM — 1 ARX = 1_000_000_000 IUM, an app-level convention (see `ArxAmount`
// on the Swift side), not a field the chain itself defines.

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountEntry {
    pub balance: u128,
    pub nonce: u64,
    pub identity_hash: Option<String>,
    // NOTE: `#[serde(default)]` does *not* make old RocksDB entries readable,
    // contrary to what this comment used to claim. Entries are bincode-encoded
    // (`BatchWritable for AccountEntry`), which is positional and emits no
    // field names, so a decoder expecting five fields hits `UnexpectedEnd` on
    // a three-field record — there is no absent-field signal for `default` to
    // fire on. The attribute is load-bearing only for a self-describing format
    // (JSON specs/fixtures), and this field arrived with a devnet genesis
    // reset, which is what actually made it safe. Appending a field here is a
    // state-breaking change.
    #[serde(default)]
    pub zk_identity_verified: bool,
    /// Which registered attestor most recently granted `identity_hash` —
    /// `None` for entries written before the attestor registry existed, or
    /// for an account that's never been attested. Doesn't (yet) drive any
    /// enforcement; it's the accountability trail a future dispute/slashing
    /// path would need, recorded now so it isn't missing retroactively.
    #[serde(default)]
    pub attested_by: Option<Address>,
    /// Which claim topics this account currently holds, granted together with
    /// `identity_hash` by `GrantAttestation`. Empty means no topic-level
    /// claims, which is not the same as "not attested" — an account attested
    /// before topics existed has an `identity_hash` and no claims, and is
    /// still accepted by assets that gate on `compliance_required`.
    ///
    /// A flat `Vec` rather than a per-topic record with its own attestor and
    /// timestamp: every topic on an account is granted by one attestor in one
    /// action today, so the extra structure would carry no information that
    /// `attested_by` doesn't already.
    #[serde(default)]
    pub claims: Vec<ClaimTopic>,
    /// Holder's jurisdiction, for assets that restrict `allowed_jurisdictions`.
    /// `None` means unknown, and an asset with a jurisdiction restriction
    /// rejects unknown rather than treating it as permitted.
    #[serde(default)]
    pub jurisdiction: Option<CountryCode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub stake: u128,
    /// Hex-encoded BLS finality key, registered into state when genesis is
    /// written. Genesis validators never run `JoinValidator`, so without this
    /// they enter the set with no way to vote — a chain that produces blocks
    /// forever and finalizes nothing. Same role as Substrate's
    /// `session.keys` in a genesis config, or the consensus pubkey inside a
    /// Cosmos gentx.
    ///
    /// Hex rather than a `BlsPublicKey` so `core/primitives` needn't depend on
    /// `core/bls`, and so the chain spec stays hand-editable — hex is the form
    /// `arxd bls-key` prints. `Option` because existing specs predate the
    /// field; a genesis validator without one is reported by `GET /finality`
    /// as unable to vote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_pubkey: Option<String>,

    /// Hex-encoded proof of possession for `bls_pubkey` — the 96-byte
    /// `xc_bls::prove_possession` signature, printed next to the key by
    /// `arxd keys`. Required whenever `bls_pubkey` is set: without it a
    /// spec author (or anyone who can edit a spec before launch) can seed a
    /// rogue key that forges finality certificates for the whole set, the
    /// same attack `RegisterBlsKey` is gated against. Enforced in
    /// `arxd_genesis::register_genesis_bls_keys`, which has the `xc-bls`
    /// dependency this crate deliberately doesn't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_pop: Option<String>,
}

/// An in-flight partial unstake on a `StakeAllocation` — v1 allows at most
/// one per `(master, validator)` pair at a time (see `StakeAllocation`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unbonding {
    pub amount: u128,
    pub unlock_at_height: u64,
}

/// A master account's stake into one validator's sub-account
/// (`circuit_staking::stake_subaccount`), owned by `circuit-staking`.
/// `active_amount` and `unbonding` coexist in the same record because a
/// partial unstake leaves part of the stake `Active` while the requested
/// part is `Unbonding` — an either/or status enum can't represent that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeAllocation {
    pub master: Address,
    pub validator: Address,
    pub active_amount: u128,
    pub unbonding: Option<Unbonding>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Deterministically derives the address staked coins for `validator` are
/// held in. Any node computes this locally — no lookup table needed.
///
/// Lives here rather than in `circuit-staking` (which re-exports it for
/// existing callers) because genesis construction (`Snapshot::batch_entries`
/// in `xc-storage`) needs it to fund a genesis validator's sub-account, and
/// `xc-storage` can't depend on `circuit-staking` — `circuit-staking` is the
/// one that depends on `xc-storage`, not the other way around. This function
/// is pure address derivation with no staking logic, so it belongs at the
/// shared base both crates already depend on.
pub fn stake_subaccount(validator: &Address) -> Address {
    // ponytail: domain-separated hash; grep confirmed no other
    // from_pubkey_bytes-as-hash usage in xc-primitives to collide with.
    let preimage = [b"xc-stake-subaccount:".as_slice(), validator.to_string().as_bytes()].concat();
    let digest = Sha256::digest(preimage);
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// Deterministic reward-pool sub-account, same derivation scheme as
/// `stake_subaccount` and the same reason for living here — genesis needs to
/// pre-fund it (see `devnet.json`'s `accounts` entry, credited directly by
/// address) without a `circuit-staking` dependency.
pub fn reward_pool_account() -> Address {
    let digest = Sha256::digest(b"xc-reward-pool");
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// Deterministic protocol-treasury sub-account, same derivation scheme.
pub fn treasury_account() -> Address {
    let digest = Sha256::digest(b"xc-treasury");
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// A membership change to the round-robin validator set, produced by a
/// chain-specific dispatch (e.g. `ActionPayload::JoinValidator`) and applied
/// generically by `xc_executor::accept_block`/`produce_block` — chain-agnostic
/// like `expected_proposer` itself, since any `P`-chain wanting round-robin
/// PoS needs the same join/leave bookkeeping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorChange {
    Join(Address, ValidatorEntry),
    Leave(Address),
}

/// Broad regulatory category, recorded so downstream consumers (Retracer's
/// listings, Console's filters) don't have to infer it from the asset id.
/// Purely descriptive — nothing in the runtime gates on it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetClass {
    #[default]
    Other,
    RealEstate,
    Equity,
    Bond,
    Stablecoin,
    Commodity,
}

/// A single attestable property of a holder. `Asset.required_claims` lists
/// which of these a holder must carry before they may send or receive.
///
/// Nothing enforces these yet: `AccountEntry` records one `identity_hash`
/// with no topic attached, so a holder is either attested or not — there's
/// no way to say "KYC'd but not Accredited". Enforcement lands with the
/// `AccountEntry`/`GrantAttestation` extension that gives attestations a
/// topic; until then `apply_compliant_transfer` falls back to
/// `compliance_required`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimTopic {
    Kyc,
    Aml,
    Accredited,
    Jurisdiction,
}

/// ISO-3166-1 alpha-2, uppercase — validated at registration rather than
/// made a distinct type.
///
// ponytail: a plain alias, no ISO crate. The workspace has no country
// dependency today and this is a two-character string; revisit if something
// ever needs to *reason* about jurisdictions (subdivisions, EU membership,
// sanctions lists) rather than just compare and display them.
pub type CountryCode = String;

/// A registered regulated asset (`ActionPayload::RegisterAsset`) — the
/// record lives in `CF_ASSETS` (`asset_record:{asset_id}`), separate from its
/// balances (also `CF_ASSETS`, one entry per `(asset_id, owner)`), which is
/// what makes asset issuance/transfer a compliance-gated overlay on top of the
/// native token rather than a replacement for it. Merkleized like balances,
/// since the compliance fields gate every transfer and must be provable in
/// the state root, not just agreed on by full nodes reading local state.
///
/// Field order is load-bearing: records are bincode-encoded
/// (`BatchWritable for Asset`), which is positional and carries no field
/// names, so reordering or removing a field silently reinterprets every
/// stored record. Append only, and deprecate in place rather than deleting.
/// Note that appending is itself a state-breaking change — see
/// `AccountEntry` for why `#[serde(default)]` does *not* make old records
/// readable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    pub asset_id: String,
    pub issuer: Address,
    /// Superseded by `required_claims`, kept because removing a field
    /// rewrites the encoding of every stored record. Authoritative only
    /// while `required_claims` is empty.
    pub compliance_required: bool,
    pub asset_class: AssetClass,
    /// Display scale only — balances are integer base units everywhere in
    /// the runtime, exactly as with the native token.
    pub decimals: u8,
    /// Empty means "fall back to `compliance_required`", not "no checks".
    pub required_claims: Vec<ClaimTopic>,
    /// `None` means unrestricted. An empty `Vec` means no jurisdiction may
    /// hold it, which is a valid (if useless) configuration rather than a
    /// synonym for `None`.
    pub allowed_jurisdictions: Option<Vec<CountryCode>>,
    /// `None` means uncapped. Enforced in `circuit_rwa_asset::apply_issue`.
    pub max_supply: Option<u128>,
    /// Cumulative issued supply, maintained by `apply_issue`. Never
    /// decreases — there's no burn action.
    pub total_supply: u128,
    /// Blocks every transfer of this asset while set. Issuance is
    /// deliberately still allowed; freezing is about circulation.
    pub frozen: bool,
    /// Off-chain pointer (prospectus, terms). Stored verbatim and never
    /// dereferenced by the node.
    pub metadata_uri: Option<String>,
    /// Height of the block that registered this asset.
    pub registered_at: u64,
}

/// The issuer-supplied half of an `Asset`: everything `RegisterAsset` carries
/// that isn't derived from the action itself. `issuer` comes from the sender,
/// `registered_at` from the block height, and `total_supply`/`frozen` always
/// start at their zero values, so none of those are settable at registration.
///
/// Grouped into a struct rather than spread across the enum variant so
/// `asset::register_asset` stays under a sane argument count, and so the
/// out-of-process codecs that mirror `ActionPayload` by hand have one shape to
/// copy instead of six loose fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub asset_class: AssetClass,
    pub decimals: u8,
    pub required_claims: Vec<ClaimTopic>,
    pub allowed_jurisdictions: Option<Vec<CountryCode>>,
    pub max_supply: Option<u128>,
    pub metadata_uri: Option<String>,
}

impl Asset {
    /// The pre-metadata three-field shape, with everything added since left
    /// at its zero value: unclassified, uncapped, unfrozen, no claims, no
    /// jurisdiction restriction. Exists so the many call sites that only
    /// care about id/issuer/gating don't each have to spell out nine
    /// defaults.
    pub fn new(asset_id: impl Into<String>, issuer: Address, compliance_required: bool) -> Self {
        Self {
            asset_id: asset_id.into(),
            issuer,
            compliance_required,
            asset_class: AssetClass::Other,
            decimals: 0,
            required_claims: Vec::new(),
            allowed_jurisdictions: None,
            max_supply: None,
            total_supply: 0,
            frozen: false,
            metadata_uri: None,
            registered_at: 0,
        }
    }

    /// The registration constructor: issuer-supplied `metadata` plus the
    /// three fields only the chain can supply. `total_supply` and `frozen`
    /// are deliberately not settable by the issuer — a newly registered asset
    /// always starts with nothing issued and circulation open.
    pub fn register(
        asset_id: impl Into<String>,
        issuer: Address,
        compliance_required: bool,
        metadata: AssetMetadata,
        registered_at: u64,
    ) -> Self {
        Self {
            asset_id: asset_id.into(),
            issuer,
            compliance_required,
            asset_class: metadata.asset_class,
            decimals: metadata.decimals,
            required_claims: metadata.required_claims,
            allowed_jurisdictions: metadata.allowed_jurisdictions,
            max_supply: metadata.max_supply,
            total_supply: 0,
            frozen: false,
            metadata_uri: metadata.metadata_uri,
            registered_at,
        }
    }
}

/// A registered KYC provider (`ActionPayload::RegisterAttestor`) — the
/// Trust Spectrum's multi-attestor model. Lives in `CF_ATTESTORS`, which is
/// merkleized: whether an address belongs to the trusted-attestor set gates
/// every `GrantAttestation`/`RevokeAttestation`, so membership must be
/// provable in the state root the same way balances are.
/// Per-(asset, holder) compliance state an issuer controls after issuance —
/// the T-REX `setAddressFrozen` / `freezePartialTokens` pair. A new key
/// (`AssetHolderStateKey`) rather than fields on the balance row, so adding
/// it changes no existing bincode layout. Absent means the default: not
/// frozen, nothing locked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderState {
    /// The holder may neither send nor receive this asset.
    pub frozen: bool,
    /// Units of the balance that cannot be spent by a compliant transfer.
    /// Forced transfers and recovery ignore it.
    pub frozen_amount: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestorRecord {
    pub name: String,
    pub registered_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub height: u64,
    pub chain_name: String,
    pub accounts: BTreeMap<Address, AccountEntry>,
    pub validators: BTreeMap<Address, ValidatorEntry>,
    /// Peer multiaddrs new nodes dial on startup to join this chain — part
    /// of the chain identity, not a per-run CLI concern. `--bootnodes` on
    /// the command line overrides this list entirely when given; empty here
    /// means rely on mDNS or an explicit CLI override.
    #[serde(default)]
    pub boot_nodes: Vec<String>,
    /// The sole address allowed to grant/revoke `identity_hash` attestations
    /// (`ActionPayload::GrantAttestation`/`RevokeAttestation`). Fixed at
    /// genesis rather than governed — see the compliance-integration plan's
    /// Stage 1 note that a governance mechanism is deferred. `Option` and
    /// `#[serde(default)]` so existing specs without compliance features
    /// still parse; a chain with no attestor simply can't grant attestations.
    #[serde(default)]
    pub attestor: Option<Address>,
    /// Address allowed to submit `RegisterAttestor`/`DeregisterAttestor` —
    /// separate from `attestor` above because deciding *who* may act as a
    /// KYC provider shouldn't require the same key to also perform KYC.
    /// Single fixed key for now, same as `attestor`; a Compliance Committee
    /// (multi-sig/voting) is the deferred upgrade for this role, not built
    /// here. `Option`/`#[serde(default)]` for the same reason as `attestor`.
    #[serde(default)]
    pub governor: Option<Address>,
}

impl Snapshot {
    /// Checks a freshly-parsed spec is fit to become a chain's genesis,
    /// before anything is written to disk or a DB is opened. Every failure
    /// case here would otherwise surface much later — as a bad directory
    /// name, a silently-wrong `meta:height`, or a BLS key rejected only
    /// after the DB is already open and the snapshot cached.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.chain_name.is_empty() {
            anyhow::bail!("chain spec has an empty chain_name");
        }
        if self.chain_name.contains('/') || self.chain_name.contains(std::path::MAIN_SEPARATOR) {
            anyhow::bail!(
                "chain spec chain_name {:?} must not contain a path separator — it becomes a directory name",
                self.chain_name
            );
        }
        if self.height != 0 {
            anyhow::bail!("chain spec height must be 0 for a genesis spec, got {}", self.height);
        }
        for addr in self.boot_nodes.iter() {
            if addr.trim().is_empty() {
                anyhow::bail!("chain spec boot_nodes contains a blank entry");
            }
        }
        for (address, entry) in &self.validators {
            if let Some(hex_pubkey) = &entry.bls_pubkey
                && hex_pubkey.len() != 96
            {
                anyhow::bail!(
                    "chain spec validator {address} has a malformed bls_pubkey {:?} — expected 96 hex chars, got {}",
                    hex_pubkey,
                    hex_pubkey.len()
                );
            }
            match (&entry.bls_pubkey, &entry.bls_pop) {
                (Some(_), None) => anyhow::bail!(
                    "chain spec validator {address} has a bls_pubkey but no bls_pop — \
                     run `arxd keys` to print both"
                ),
                (Some(_), Some(pop)) if pop.len() != 192 => anyhow::bail!(
                    "chain spec validator {address} has a malformed bls_pop {:?} — expected \
                     192 hex chars, got {}",
                    pop,
                    pop.len()
                ),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `arxd keys` emits a chain-spec entry by serializing `ValidatorEntry`
    /// itself, and `genesis`/`xc_chain_spec` parse the spec back into `Snapshot`. This
    /// pins that round trip: an entry the command prints must be an entry the
    /// loader accepts, with the BLS key surviving intact. A rename or a serde
    /// attribute change on either side would produce output that looks correct
    /// and silently registers no key.
    #[test]
    fn a_validator_entry_round_trips_through_the_chain_spec_format() {
        let address = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();
        let bls = "b9e633ef84a4f0a8e522992c72ffe1234607c5cb71d7faba476b80164edda056d\
                   2efb5df47592a7206c4c2eaff5287d6";

        let emitted = serde_json::to_string(&BTreeMap::from([(
            address.clone(),
            ValidatorEntry { stake: 100_000 * 1_000_000_000, bls_pubkey: Some(bls.into()), bls_pop: None },
        )]))
        .unwrap();

        let spec = format!(
            r#"{{"height":0,"chain_name":"t","accounts":{{}},"validators":{emitted},"boot_nodes":[]}}"#
        );
        let snapshot: Snapshot = serde_json::from_str(&spec).expect("spec must parse");

        let entry = snapshot.validators.get(&address).expect("validator must survive");
        assert_eq!(entry.stake, 100_000 * 1_000_000_000);
        assert_eq!(
            entry.bls_pubkey.as_deref(),
            Some(bls),
            "the BLS key must survive the round trip, or genesis registers nothing",
        );
    }

    /// Specs written before `bls_pubkey` existed must still parse — the field
    /// is `Option` with `serde(default)` for exactly this reason. Such a
    /// validator is reported by `GET /finality` as unable to vote rather than
    /// crashing the node at boot.
    #[test]
    fn a_spec_without_bls_pubkey_still_parses() {
        let spec = r#"{
            "height": 0,
            "chain_name": "t",
            "accounts": {},
            "validators": {
                "arx1qgz5uv6kwzy0zx9lyup4t7chwff3rce0mfwsu2ryayr0e9dkhx7qc0wq2f": {"stake": 1000000}
            },
            "boot_nodes": []
        }"#;
        let snapshot: Snapshot = serde_json::from_str(spec).expect("legacy spec must parse");
        let entry = snapshot.validators.values().next().unwrap();
        assert_eq!(entry.stake, 1_000_000);
        assert!(entry.bls_pubkey.is_none());
    }
}
