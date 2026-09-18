//! CoreChain's action payload, and nothing else — the one type an
//! out-of-process reader (Retracer, an indexer) needs to decode blocks.
//! Leaf crate on purpose: depends only on `xc-primitives` + serde, so a
//! consumer can pin it without pulling in circuits, storage or the
//! runtime. Variant order is the wire format; append, never reorder.
use serde::{Deserialize, Serialize};
use xc_primitives::{Action, Address, AssetMetadata, AssetRef, ClaimTopic, CountryCode};

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer {
        to: Address,
        amount: u128,
    },
    /// Staking to join the validator set: routed through
    /// `circuit_staking::apply_stake` with `master == sender`, so it's held
    /// in the same `stake_subaccount` mechanism regular delegators use —
    /// same balance check, same "already controlled by another master"
    /// rejection, no new bookkeeping. Takes effect one block after this
    /// action lands (`xc_executor::accept_block`'s effective-height rule) —
    /// can't vote itself into this block's own proposer slot. `stake` on
    /// `ValidatorEntry` is informational only; `ValidatorSetSnapshot` never
    /// persists it, so the `StakeAllocation` for `(sender, validator)` is the
    /// real source of truth for how much a validator has at stake.
    ///
    /// `sender == validator` for ordinary self-service joining. `sender !=
    /// validator` is a *delegated* join — `sender` must be `validator`'s
    /// authorized operator (see `AuthorizeOperator`), and `sender`'s own
    /// balance funds the stake, same as a third-party `Stake` action. That
    /// also means `sender` becomes `validator`'s stake master going forward
    /// (`circuit_staking::apply_stake`'s single-master invariant) — the
    /// validator can't separately self-stake later while a delegated master
    /// holds that slot.
    JoinValidator {
        validator: Address,
        stake: u128,
        /// The validator's BLS finality key, registered atomically with the
        /// join. Required, not optional: a validator without one is counted
        /// toward the finality quorum while being unable to vote, so every
        /// such validator raises the threshold and contributes nothing to
        /// meeting it. Enough of them and the chain produces blocks forever
        /// while finalizing nothing, with no symptom but a warning per
        /// dropped vote.
        ///
        /// Carried in the action rather than required as a prior
        /// `RegisterBlsKey` so joining is atomic and cannot half-succeed —
        /// this is Cosmos's `MsgCreateValidator.pubkey`. `RegisterBlsKey`
        /// remains, for rotating a key on an existing validator.
        bls_pubkey: Vec<u8>,
        /// Proof of possession for `bls_pubkey` — `xc_bls::prove_possession`,
        /// printed alongside the key by `arxd keys`. Without it a rogue key
        /// forges quorum certificates; see `consensus::validated_bls_pubkey`.
        bls_pop: Vec<u8>,
    },
    /// Removal from the validator set, routed through
    /// `circuit_staking::apply_unstake` for `validator`'s full self-stake
    /// and a `Leaving` status. The validator keeps proposing and voting
    /// until the epoch boundary, then drops; the stake sits in `Unbonding`
    /// for `ChainParams::unbonding_blocks` — and stays
    /// slashable that whole time (`circuit_staking::apply_slash` treats
    /// unbonding funds as fair game). Rejected if `validator` isn't
    /// currently a validator, or if they're the last one — an empty
    /// validator set means `expected_proposer` returns `None` forever and
    /// the chain can never produce another block (the same deadlock hit live
    /// this session from running `--bootnode` on two machines,
    /// self-inflicted here instead).
    ///
    /// `sender == validator` for self-service leaving. `sender != validator`
    /// is delegated — same authorization rule as `JoinValidator` — and the
    /// unstaked funds return to whoever `validator`'s recorded master is
    /// (`sender` in the self-service case, the authorized operator in the
    /// delegated case), never anywhere else.
    LeaveValidator {
        validator: Address,
    },
    /// MW-signature-only stake into a validator's sub-account
    /// (`circuit_staking::stake_subaccount`). See `circuit_staking::apply_stake`.
    Stake {
        validator: Address,
        amount: u128,
    },
    /// MW-signature-only partial or full unstake, subject to
    /// `ChainParams::unbonding_blocks`. See `circuit_staking::apply_unstake`.
    /// There is deliberately no `Slash` variant here — slashing is never
    /// user-submitted, so it's unreachable from RPC/mempool by construction
    /// (see `circuit_staking::apply_slash`).
    Unstake {
        validator: Address,
        amount: u128,
    },
    /// Proof that a validator signed two different blocks at the same
    /// height — normally built and submitted by `xc_evidence::spawn_evidence_watcher`
    /// when it observes a competing block, never hand-crafted by an
    /// ordinary user. Anyone *could* submit one given the two blocks, but
    /// `xc_evidence::verify_equivocation` is what actually gates the slash, not
    /// who submitted it — so that's fine.
    SubmitEquivocationEvidence {
        block_a: Box<ChainBlock>,
        block_b: Box<ChainBlock>,
    },
    /// Registers `validator`'s BLS pubkey for finality-certificate
    /// precommit voting (`arxd/finality`). Any address may be registered —
    /// the key is only meaningful once/if that address is also in the
    /// validator set at some height; no membership check happens here.
    /// `sender == validator` for self-registration; `sender != validator` is
    /// delegated, same authorization rule as `JoinValidator`. This lets a
    /// validator's operator register the key on its behalf without the
    /// validator's own key ever leaving the machine it was generated on
    /// (`arxd bls-key`).
    RegisterBlsKey {
        validator: Address,
        pubkey: Vec<u8>,
        /// Proof of possession for `pubkey` — see `JoinValidator::bls_pop`.
        pop: Vec<u8>,
    },
    /// A Groth16 proof of knowledge of a preimage hashing (via
    /// `circuit_identity_zk`'s Poseidon circuit) to the sender's existing
    /// `AccountEntry.identity_hash`. Verified against the checked-in devnet
    /// verifying key — see `circuits/identity-zk`'s module docs for why
    /// that key isn't from a real trusted-setup ceremony. On success, marks
    /// `zk_identity_verified` on the sender's account.
    VerifyIdentityCredential {
        proof: Vec<u8>,
    },
    /// Grants `operator` authority to submit `JoinValidator`/
    /// `LeaveValidator`/`RegisterBlsKey` on the sender's behalf — self-signed
    /// only, this is how a validator opts in to delegated management, never
    /// something an operator can grant itself. Overwrites any previously
    /// authorized operator (at most one at a time, mirroring
    /// `circuit_staking::apply_stake`'s single-master invariant).
    ///
    /// Appended here rather than inserted among the existing variants —
    /// `ActionPayload`'s wire format (bincode, used for gossip/sync, and
    /// hand-mirrored by out-of-process codecs like Arx-Plus's Swift one)
    /// encodes enum variants by discriminant index, so inserting earlier
    /// would silently shift every later variant's index.
    AuthorizeOperator {
        operator: Address,
    },
    /// Revokes the sender's currently authorized operator, if any —
    /// self-signed only, so a validator can always unilaterally cut off a
    /// compromised or unwanted operator regardless of what that operator
    /// does or doesn't do.
    RevokeOperator,
    /// Marks `subject` eligible (sets `AccountEntry.identity_hash`) — only
    /// a registered attestor (membership in `CF_ATTESTORS`, managed via
    /// `RegisterAttestor`/`DeregisterAttestor`) may submit this. Records
    /// `sender` in `AccountEntry.attested_by` for accountability.
    GrantAttestation {
        subject: Address,
        hash: String,
        /// Which claim topics this attestation confers. Empty grants an
        /// `identity_hash` and nothing topic-level, which is what every
        /// attestation did before topics existed and is still enough for
        /// assets that gate on `compliance_required`.
        topics: Vec<ClaimTopic>,
        /// Subject's jurisdiction, for assets restricting
        /// `allowed_jurisdictions`. `None` leaves it unknown, and an asset
        /// with a restriction rejects unknown rather than permitting it.
        jurisdiction: Option<CountryCode>,
    },
    /// Reverses `GrantAttestation` — clears `identity_hash` and, since a
    /// revoked KYC status shouldn't leave a stale ZK-verified flag around,
    /// also clears `zk_identity_verified`. Any registered attestor may
    /// revoke any attestation (permissive revocation), not just the one
    /// that granted it.
    RevokeAttestation {
        subject: Address,
    },
    /// Registers a new regulated asset, `sender` becoming its issuer. The
    /// asset's chain-wide identity is `AssetRef::derive(sender, asset_id)`;
    /// `asset_id` is only a slug, unique within the sender. Rejected if the
    /// sender already has an asset with this slug, or if `asset_id` /
    /// `metadata` fail `asset::register_asset`'s validation.
    ///
    /// The only asset variant that still carries `asset_id: String` — it is
    /// the slug being claimed. Every other asset variant names the asset by
    /// `AssetRef`, so nothing downstream ever resolves by slug or symbol.
    ///
    /// `metadata` was added to this variant in place rather than as a new
    /// variant: bincode encodes struct-variant fields positionally, so this
    /// changes the encoding and old blocks carrying the two-field form no
    /// longer decode. That is acceptable only because devnet genesis is being
    /// reset alongside it — on a live chain this would need a new variant
    /// appended instead. The `AssetRef` re-key happened on the same reasoning
    /// in the same reset. Retracer's hand-mirrored copy of this enum
    /// (`crates/ingestion/src/corechain_payload.rs`) must gain the same
    /// fields, in this position, in the same release.
    RegisterAsset {
        asset_id: String,
        compliance_required: bool,
        metadata: AssetMetadata,
    },
    /// Mints `amount` of `asset` into the issuer's own asset balance —
    /// only the registered issuer may call this. Native balance untouched.
    IssueAsset {
        asset: AssetRef,
        amount: u128,
    },
    /// Compliance-gated transfer of a registered asset — distinct from
    /// `Transfer`, which only ever moves the native token and is never
    /// KYC-gated.
    TransferAsset {
        asset: AssetRef,
        to: Address,
        amount: u128,
    },
    /// Adds `attestor` to the trusted-attestor set (the attestor admin
    /// only, see `Snapshot.attestor_admin`) — the Trust Spectrum's multi-attestor
    /// model: more than one regulated KYC provider can hold
    /// `GrantAttestation`/`RevokeAttestation` rights at once. Rejected if
    /// `attestor` is already registered.
    RegisterAttestor {
        attestor: Address,
        name: String,
        reason: String,
    },
    /// Removes `attestor` from the trusted-attestor set (attestor admin
    /// only). Any registered attestor may still revoke attestations that
    /// `attestor` previously granted — see `identity::require_attestor`.
    DeregisterAttestor {
        attestor: Address,
        reason: String,
    },
    /// Submits a `Fault::ActionDivergence`/`Fault::BlockDivergence` evidence
    /// artifact (JSON-serialized `xc_artifact::EvidenceArtifact`) for
    /// on-chain adjudication and slashing — the counterpart to
    /// `SubmitEquivocationEvidence` for the two fault kinds that need
    /// chain-specific replay (see `adjudicate`) rather than a
    /// context-free signature/proof check to name a culprit. Anyone may
    /// submit one, same as equivocation evidence — `adjudicate::*` and the
    /// artifact's own signatures are what gate the slash, not who
    /// submitted it.
    SubmitExecutionFault {
        artifact_json: String,
    },
    /// Halts all transfers of `asset` until an `UnfreezeAsset` lands.
    /// Issuance is deliberately unaffected — a freeze is about circulation,
    /// not about sealing the supply.
    ///
    /// Appended here, not inserted: see `AuthorizeOperator` above for why
    /// variant order is part of the wire format. Retracer keeps a
    /// hand-mirrored copy of this enum
    /// (`crates/ingestion/src/corechain_payload.rs`) that has to gain the
    /// same variants in the same order, or it will misdecode blocks rather
    /// than fail on them.
    FreezeAsset {
        asset: AssetRef,
        reason: String,
    },
    /// Lifts a `FreezeAsset`. Idempotent — unfreezing an asset that isn't
    /// frozen succeeds rather than erroring, so an admin never has to know
    /// the current flag to reach the state they want.
    UnfreezeAsset {
        asset: AssetRef,
        reason: String,
    },
    /// Moves `amount` of `asset` from `from` to `to` without `from`'s
    /// signature and without any compliance, claim, jurisdiction or freeze
    /// check — the recovery admin only. This is the recovery and enforcement
    /// path for what compliance cannot express: a court-ordered
    /// reassignment, a sanctioned holder, a holder who has lost their key.
    /// It still cannot mint: `from` must actually hold the balance.
    ///
    /// `reason` is mandatory and non-empty — as on every other admin-gated
    /// action (`RegisterAttestor`/`DeregisterAttestor`/`FreezeAsset`/
    /// `UnfreezeAsset`), so each privileged act is attributable *and*
    /// justified. It is not stored in state — it lives in the block that
    /// carried the action, which is the durable, replicated audit record a
    /// regulator would be shown, and keeping it out of state avoids growing
    /// the trie with free-text an issuer controls.
    ///
    /// Appended, like `FreezeAsset`/`UnfreezeAsset` above; the same note
    /// about Retracer's mirrored enum applies.
    ForcedTransfer {
        asset: AssetRef,
        from: Address,
        to: Address,
        amount: u128,
        reason: String,
    },
    /// Issuer destroys `amount` of its own balance; `total_supply` follows.
    /// Variant 21 — appended, so Retracer's mirror and the client codecs must
    /// add it in this position.
    BurnAsset {
        asset: AssetRef,
        amount: u128,
    },
    /// Issuer takes a holder out of circulation for one asset (or back in) —
    /// Variant 22.
    SetHolderFrozen {
        asset: AssetRef,
        holder: Address,
        frozen: bool,
    },
    /// Issuer locks `amount` of a holder's balance against compliant
    /// transfers. Variant 23.
    LockHolderAmount {
        asset: AssetRef,
        holder: Address,
        amount: u128,
    },
    /// Reverses `LockHolderAmount`. Variant 24.
    UnlockHolderAmount {
        asset: AssetRef,
        holder: Address,
        amount: u128,
    },
    /// The issuer's own forced transfer, scoped to assets it issued, same audited `reason` as the
    /// recovery admin's `ForcedTransfer`. Variant 25.
    IssuerForcedTransfer {
        asset: AssetRef,
        from: Address,
        to: Address,
        amount: u128,
        reason: String,
    },
    /// Move everything `lost` holds of an asset to `replacement`, which must
    /// pass the asset's compliance rules. Issuer
    /// only. Variant 26.
    RecoverHolder {
        asset: AssetRef,
        lost: Address,
        replacement: Address,
    },
    /// Issuer mints straight into a verified investor's balance. `to` passes the asset's compliance rules; the issuer,
    /// which never holds the units, is not checked. Variant 27.
    IssueAssetTo {
        asset: AssetRef,
        to: Address,
        amount: u128,
    },
    /// Issuer permanently gives up the right to mint `asset`: sets
    /// `Asset.issuance_locked` and pins `max_supply` to the current
    /// `total_supply`. A burn after this is final — nothing can refill the
    /// cap room it frees. Issuer only, one-way, idempotent. Variant 28.
    LockIssuance {
        asset: AssetRef,
    },
    /// Issuer hands every issuer right over `asset` to `new_issuer` — key
    /// rotation and the compromise remedy. Variant 29.
    TransferIssuer {
        asset: AssetRef,
        new_issuer: Address,
    },
    /// Issuer repoints `metadata_uri` (prospectus, terms). Variant 30.
    SetAssetMetadataUri {
        asset: AssetRef,
        metadata_uri: Option<String>,
    },
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire discriminants the out-of-process codecs (Arx-Plus Swift, Console
    /// TS, Retracer) have hard-coded. Inserting a variant mid-enum shifts
    /// every later index and fails here instead of on a phone.
    #[test]
    fn variant_discriminants_are_pinned() {
        const EXPECTED: [&str; 31] = [
            "Transfer",
            "JoinValidator",
            "LeaveValidator",
            "Stake",
            "Unstake",
            "SubmitEquivocationEvidence",
            "RegisterBlsKey",
            "VerifyIdentityCredential",
            "AuthorizeOperator",
            "RevokeOperator",
            "GrantAttestation",
            "RevokeAttestation",
            "RegisterAsset",
            "IssueAsset",
            "TransferAsset",
            "RegisterAttestor",
            "DeregisterAttestor",
            "SubmitExecutionFault",
            "FreezeAsset",
            "UnfreezeAsset",
            "ForcedTransfer",
            "BurnAsset",
            "SetHolderFrozen",
            "LockHolderAmount",
            "UnlockHolderAmount",
            "IssuerForcedTransfer",
            "RecoverHolder",
            "IssueAssetTo",
            "LockIssuance",
            "TransferIssuer",
            "SetAssetMetadataUri",
        ];
        let cfg = bincode::config::standard();
        for (idx, name) in EXPECTED.iter().enumerate() {
            // Discriminant byte, then zeros: every field decodes as empty/0/None.
            let mut bytes = vec![idx as u8];
            bytes.extend([0u8; 256]);
            let (decoded, _): (ActionPayload, _) = bincode::serde::decode_from_slice(&bytes, cfg)
                .unwrap_or_else(|e| panic!("variant {idx} ({name}) failed to decode: {e}"));
            let debug = format!("{decoded:?}");
            let got = debug.split([' ', '{']).next().unwrap();
            assert_eq!(got, *name, "variant index {idx}");
        }
        let past_end = [EXPECTED.len() as u8, 0];
        assert!(
            bincode::serde::decode_from_slice::<ActionPayload, _>(&past_end, cfg).is_err(),
            "new variant appended without updating EXPECTED"
        );
    }
}
