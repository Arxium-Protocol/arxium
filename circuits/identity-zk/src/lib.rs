// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Toy zk credential-proof circuit: proves knowledge of a preimage `x` such
//! that `Poseidon(x) == credential_hash`, matching
//! `AccountEntry.identity_hash`. Groth16 over BLS12-381 (arkworks), per the
//! whitepaper's Native Identity Architecture — this is one minimal
//! statement, not the full Trust Spectrum.
//!
//! The statement carries a second public input, `sender`: the account
//! submitting the proof. It isn't part of the hash relation, it's there so
//! the proof is bound to one account — without it, a proof observed on-chain
//! verifies just as well from any other account attested to the same
//! `credential_hash`. The verifier derives `sender` from `action.sender`,
//! never from the proof, so a replayed proof simply fails to verify.
//!
//! `setup()` runs its own circuit-specific Groth16 parameter generation.
//! **This is not a real trusted-setup ceremony** — the toxic waste (the RNG
//! seed) is not destroyed via multi-party computation, it's just a test RNG
//! in this process. Fine for devnet; replace with a real ceremony before any
//! real credential data flows through this circuit.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::RngCore;
use sha2::{Digest, Sha256};

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};

/// Devnet Groth16 verifying key, checked into this crate — see the module
/// docs above for why it isn't from a real trusted-setup ceremony.
pub const VK_BYTES: &[u8] = include_bytes!("../vk.bin");
/// Devnet key for the standalone, no-attestation sign-in proof.
/// Generated with `cargo run -p circuit-identity-zk --example generate_keys`.
pub const SIGN_IN_VK_BYTES: &[u8] = include_bytes!("../sign_in_vk.bin");
pub const PREDICATE_VK_BYTES: &[u8] = include_bytes!("../predicate_vk.bin");

pub mod predicate;

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const ALPHA: u64 = 5;
pub const ATTESTED_TREE_DEPTH: usize = 20;
/// Days between 1900-01-01 and the Unix epoch, for the v1 credential's
/// unsigned date fields. This permits birth dates before 1970.
pub const CREDENTIAL_EPOCH_OFFSET_DAYS: u32 = 25_567;

/// ISO 3166-1 alpha-2 assignments from the public-domain IANA zoneinfo
/// `iso3166.tab` (ISO/TC 46 N1108, 2023-04-05). Shared by attestors, the
/// wallet importer and the node so a claim request cannot use an unassigned
/// country guess.
pub const ISO3166_ALPHA2: &str = concat!(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ ",
    "BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ",
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ ",
    "DE DJ DK DM DO DZ EC EE EG EH ER ES ET ",
    "FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY ",
    "HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT ",
    "JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ ",
    "LA LB LC LI LK LR LS LT LU LV LY ",
    "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ ",
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM ",
    "PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW ",
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ ",
    "TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ ",
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
);

pub fn valid_country_code(code: &str) -> bool {
    code.len() == 2
        && ISO3166_ALPHA2
            .split_ascii_whitespace()
            .any(|candidate| candidate == code)
}

/// Devnet-fixed Poseidon parameters over BLS12-381's scalar field. Not a
/// security-critical choice — this circuit's only job is exercising the
/// prove/verify pipeline end to end.
pub fn poseidon_params() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
}

/// Maps arbitrary bytes (e.g. a credential preimage) onto the scalar field.
pub fn hash_to_field(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// RFC 5869 HKDF-SHA256 with an all-zero salt and `arx-id/v1` as info.
/// Expands to 64 bytes before reduction to avoid restricting the secret to
/// the 256-bit output of a single SHA-256 invocation. The seed never leaves
/// the wallet; callers should clear temporary seed copies after use.
pub fn derive_id_secret(wallet_seed: &[u8]) -> Fr {
    fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut pad = [0u8; 64];
        pad[..key.len()].copy_from_slice(key);
        let mut inner = pad;
        for byte in &mut inner {
            *byte ^= 0x36;
        }
        let digest = Sha256::digest([inner.as_slice(), message].concat());
        for byte in &mut pad {
            *byte ^= 0x5c;
        }
        Sha256::digest([pad.as_slice(), digest.as_slice()].concat()).into()
    }
    let prk = hmac(&[0u8; 32], wallet_seed);
    let first = hmac(&prk, b"arx-id/v1\x01");
    let second = hmac(&prk, &[first.as_slice(), b"arx-id/v1\x02"].concat());
    hash_to_field(&[first.as_slice(), second.as_slice()].concat())
}

/// Poseidon(preimage) over the scalar field — the value stored as
/// `AccountEntry.identity_hash`.
pub fn credential_hash(params: &PoseidonConfig<Fr>, preimage: &[u8]) -> Fr {
    CRH::<Fr>::evaluate(params, vec![hash_to_field(preimage)]).expect("poseidon evaluate")
}

/// The `sender` public input as a field element — the account's raw public
/// key bytes mapped the same way `hash_to_field` maps a preimage.
pub fn sender_binding(sender_pubkey: &[u8]) -> Fr {
    hash_to_field(sender_pubkey)
}

/// Versioned, fixed-width opening given to the holder by the attestor.
/// Integers are encoded as field elements in the order documented in
/// `credential_leaf`. Dates are unsigned UTC calendar days since 1900-01-01;
/// country_code is two uppercase ASCII bytes, big endian.
#[derive(Clone, Debug)]
pub struct CredentialOpening {
    pub kyc: bool,
    pub aml: bool,
    pub accredited: bool,
    pub birth_date_days: u32,
    pub country_code: [u8; 2],
    pub membership_root: Fr,
    pub expiry_days: u32,
    pub salt: Fr,
}

/// Canonical v1 leaf format. The attestor receives `id_commitment`, not the
/// secret; the holder checks that the returned opening recomputes this leaf.
pub fn credential_leaf(
    params: &PoseidonConfig<Fr>,
    id_commitment: Fr,
    opening: &CredentialOpening,
) -> Fr {
    let country = u16::from_be_bytes(opening.country_code);
    CRH::<Fr>::evaluate(
        params,
        vec![
            Fr::from(1u64),
            id_commitment,
            Fr::from(u64::from(opening.kyc)),
            Fr::from(u64::from(opening.aml)),
            Fr::from(u64::from(opening.accredited)),
            Fr::from(opening.birth_date_days),
            Fr::from(country),
            opening.membership_root,
            Fr::from(opening.expiry_days),
            opening.salt,
        ],
    )
    .expect("poseidon leaf")
}

/// Canonical scope: SHA-256 of the domain label followed by the gateway's
/// account ID, reduced into the BLS12-381 scalar field before Poseidon.
pub fn asker_scope(params: &PoseidonConfig<Fr>, asker_account_id: &str) -> Fr {
    let digest =
        Sha256::digest([b"arx-id-scope/v1".as_slice(), asker_account_id.as_bytes()].concat());
    CRH::<Fr>::evaluate(params, vec![hash_to_field(&digest)]).expect("poseidon scope")
}

/// On-chain claim proofs (`VerifyClaimProof`) use the asset as the scope, so
/// a proof made for one asset can't clear another asset's gate. Separate
/// domain label from `asker_scope`: a gateway account id can never collide
/// with an asset ref.
pub fn asset_scope(params: &PoseidonConfig<Fr>, asset_ref: &str) -> Fr {
    let digest = Sha256::digest([b"arx-rwa-scope/v1".as_slice(), asset_ref.as_bytes()].concat());
    CRH::<Fr>::evaluate(params, vec![hash_to_field(&digest)]).expect("poseidon scope")
}

/// Stable within an asker account, unlinkable between independently scoped
/// accounts. Both plain sign-in and credential proofs must use this function.
pub fn derive_sub(params: &PoseidonConfig<Fr>, id_secret: Fr, scope: Fr) -> Fr {
    CRH::<Fr>::evaluate(params, vec![id_secret, scope]).expect("poseidon sub")
}

pub fn id_commitment(params: &PoseidonConfig<Fr>, id_secret: Fr) -> Fr {
    CRH::<Fr>::evaluate(params, vec![id_secret]).expect("poseidon commitment")
}

/// Fixed-depth tree with zero-valued empty leaves. The same indexed ordering
/// must be used by the node and the wallet; removing a leaf replaces it with
/// zero instead of shifting the remaining indices.
#[derive(Clone, Debug)]
pub struct AttestedTree {
    levels: Vec<Vec<Fr>>,
    zeros: Vec<Fr>,
}

impl AttestedTree {
    pub fn from_leaves(params: &PoseidonConfig<Fr>, leaves: &[Fr]) -> Option<Self> {
        if leaves.len() > (1 << ATTESTED_TREE_DEPTH) {
            return None;
        }
        let mut zeros = vec![Fr::from(0u64)];
        for depth in 0..ATTESTED_TREE_DEPTH {
            zeros.push(poseidon_pair(params, zeros[depth], zeros[depth]));
        }
        let mut levels = vec![leaves.to_vec()];
        for depth in 0..ATTESTED_TREE_DEPTH {
            let current = &levels[depth];
            let parents = current
                .chunks(2)
                .map(|pair| poseidon_pair(params, pair[0], *pair.get(1).unwrap_or(&zeros[depth])))
                .collect();
            levels.push(parents);
        }
        Some(Self { levels, zeros })
    }

    pub fn root(&self) -> Fr {
        self.levels[ATTESTED_TREE_DEPTH]
            .first()
            .copied()
            .unwrap_or(self.zeros[ATTESTED_TREE_DEPTH])
    }

    /// Replace a leaf at its current position and recompute only the twenty
    /// ancestors. Removed leaves become zero without shifting other slots.
    /// The node rebuilds if the ordered set changes length.
    pub fn replace_leaf(
        &mut self,
        params: &PoseidonConfig<Fr>,
        mut index: usize,
        value: Fr,
    ) -> Option<()> {
        if index >= self.levels[0].len() {
            return None;
        }
        self.levels[0][index] = value;
        for depth in 0..ATTESTED_TREE_DEPTH {
            let left_index = index & !1;
            let left = self.levels[depth][left_index];
            let right = self.levels[depth]
                .get(left_index + 1)
                .copied()
                .unwrap_or(self.zeros[depth]);
            index >>= 1;
            self.levels[depth + 1][index] = poseidon_pair(params, left, right);
        }
        Some(())
    }

    pub fn path(&self, mut index: usize) -> Option<[Fr; ATTESTED_TREE_DEPTH]> {
        if index >= self.levels[0].len() {
            return None;
        }
        let mut path = [Fr::from(0u64); ATTESTED_TREE_DEPTH];
        for (depth, sibling) in path.iter_mut().enumerate() {
            *sibling = self.levels[depth]
                .get(index ^ 1)
                .copied()
                .unwrap_or(self.zeros[depth]);
            index >>= 1;
        }
        Some(path)
    }
}

pub fn poseidon_pair(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    CRH::<Fr>::evaluate(params, vec![left, right]).expect("poseidon tree node")
}

pub fn root_from_path(
    params: &PoseidonConfig<Fr>,
    mut leaf: Fr,
    mut index: usize,
    path: &[Fr; ATTESTED_TREE_DEPTH],
) -> Fr {
    for sibling in path {
        leaf = if index & 1 == 0 {
            poseidon_pair(params, leaf, *sibling)
        } else {
            poseidon_pair(params, *sibling, leaf)
        };
        index >>= 1;
    }
    leaf
}

/// Plain sign-in deliberately has no credential witness: a wallet without an
/// attestation can prove its stable scoped identifier. The gateway supplies
/// the scope and nonce and must check both against its single-use request.
#[derive(Clone)]
pub struct SignInCircuit {
    pub params: PoseidonConfig<Fr>,
    pub id_secret: Option<Fr>,
    pub sub: Option<Fr>,
    pub scope: Option<Fr>,
    pub nonce: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SignInCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let sub = FpVar::new_input(cs.clone(), || {
            self.sub.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let scope = FpVar::new_input(cs.clone(), || {
            self.scope.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nonce = FpVar::new_input(cs.clone(), || {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let secret = FpVar::new_witness(cs.clone(), || {
            self.id_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nonce_copy = FpVar::new_witness(cs.clone(), || {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Binding a public input only by listing it is insufficient: an
        // unconstrained input has a zero column in Groth16's verification key.
        nonce_copy.enforce_equal(&nonce)?;
        let params = CRHParametersVar::new_constant(cs, self.params)?;
        CRHGadget::<Fr>::evaluate(&params, &[secret, scope])?.enforce_equal(&sub)
    }
}

/// Generate a distinct devnet setup for the no-attestation circuit.
pub fn setup_sign_in<R: RngCore + ark_std::rand::CryptoRng>(
    rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(
        SignInCircuit {
            params: poseidon_params(),
            id_secret: None,
            sub: None,
            scope: None,
            nonce: None,
        },
        rng,
    )
    .expect("sign-in setup")
}

pub fn prove_sign_in<R: RngCore + ark_std::rand::CryptoRng>(
    secret: Fr,
    scope: Fr,
    nonce: Fr,
    pk: &ProvingKey<Bls12_381>,
    rng: &mut R,
) -> Proof<Bls12_381> {
    let params = poseidon_params();
    ark_groth16::Groth16::<Bls12_381>::prove(
        pk,
        SignInCircuit {
            sub: Some(derive_sub(&params, secret, scope)),
            params,
            id_secret: Some(secret),
            scope: Some(scope),
            nonce: Some(nonce),
        },
        rng,
    )
    .expect("sign-in prove")
}

pub fn verify_sign_in(
    sub: Fr,
    scope: Fr,
    nonce: Fr,
    proof: &Proof<Bls12_381>,
    vk: &VerifyingKey<Bls12_381>,
) -> bool {
    ark_groth16::Groth16::<Bls12_381>::verify(vk, &[sub, scope, nonce], proof).unwrap_or(false)
}

#[derive(Clone)]
pub struct PreimageCircuit {
    pub params: PoseidonConfig<Fr>,
    pub preimage: Option<Fr>,
    pub credential_hash: Option<Fr>,
    pub sender: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for PreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let hash_var = FpVar::new_input(cs.clone(), || {
            self.credential_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sender_var = FpVar::new_input(cs.clone(), || {
            self.sender.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let preimage_var = FpVar::new_witness(cs.clone(), || {
            self.preimage.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // A public input that appears in no constraint has a zero column in
        // the QAP and so a zero `gamma_abc` term — the verifier would accept
        // any value for it. One linear constraint against a witness copy is
        // enough to give it a non-zero column and make the binding real.
        let sender_witness = FpVar::new_witness(cs.clone(), || {
            self.sender.ok_or(SynthesisError::AssignmentMissing)
        })?;
        sender_witness.enforce_equal(&sender_var)?;
        let params_var = CRHParametersVar::new_constant(cs, self.params)?;
        let computed = CRHGadget::<Fr>::evaluate(&params_var, &[preimage_var])?;
        computed.enforce_equal(&hash_var)
    }
}

/// Circuit-specific Groth16 setup. See module docs — devnet only.
pub fn setup<R: RngCore + ark_std::rand::CryptoRng>(
    rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let circuit = PreimageCircuit {
        params: poseidon_params(),
        preimage: None,
        credential_hash: None,
        sender: None,
    };
    ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng).expect("groth16 setup")
}

/// `sender` is the raw public key of the account that will submit the proof
/// (see `sender_binding`); the proof verifies for that account only.
pub fn prove<R: RngCore + ark_std::rand::CryptoRng>(
    preimage: &[u8],
    sender: &[u8],
    pk: &ProvingKey<Bls12_381>,
    rng: &mut R,
) -> Proof<Bls12_381> {
    let params = poseidon_params();
    let preimage_fr = hash_to_field(preimage);
    let circuit = PreimageCircuit {
        params: params.clone(),
        preimage: Some(preimage_fr),
        credential_hash: Some(credential_hash(&params, preimage)),
        sender: Some(sender_binding(sender)),
    };
    ark_groth16::Groth16::<Bls12_381>::prove(pk, circuit, rng).expect("groth16 prove")
}

pub fn verify(
    credential_hash: &Fr,
    sender: &Fr,
    proof: &Proof<Bls12_381>,
    vk: &VerifyingKey<Bls12_381>,
) -> bool {
    ark_groth16::Groth16::<Bls12_381>::verify(vk, &[*credential_hash, *sender], proof)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    const ALICE: &[u8] = &[1u8; 32];

    #[test]
    fn prove_and_verify_roundtrip_with_correct_preimage() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let preimage = b"correct horse battery staple";
        let proof = prove(preimage, ALICE, &pk, &mut rng);
        let hash = credential_hash(&poseidon_params(), preimage);
        assert!(verify(&hash, &sender_binding(ALICE), &proof, &vk));
    }

    #[test]
    fn verify_rejects_wrong_preimage() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let proof = prove(b"correct horse battery staple", ALICE, &pk, &mut rng);
        let wrong_hash = credential_hash(&poseidon_params(), b"wrong guess");
        assert!(!verify(&wrong_hash, &sender_binding(ALICE), &proof, &vk));
    }

    /// The replay case: a proof Alice published verifies for nobody else,
    /// even with the exact same credential hash.
    #[test]
    fn verify_rejects_a_proof_bound_to_another_sender() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let preimage = b"correct horse battery staple";
        let proof = prove(preimage, ALICE, &pk, &mut rng);
        let hash = credential_hash(&poseidon_params(), preimage);
        assert!(verify(&hash, &sender_binding(ALICE), &proof, &vk));
        assert!(!verify(&hash, &sender_binding(&[2u8; 32]), &proof, &vk));
    }

    #[test]
    fn verify_rejects_tampered_proof_bytes() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let preimage = b"correct horse battery staple";
        let proof = prove(preimage, ALICE, &pk, &mut rng);
        let hash = credential_hash(&poseidon_params(), preimage);

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        bytes[0] ^= 0xff;

        // A flipped byte either fails to deserialize into a well-formed
        // proof at all, or deserializes into one that fails verification —
        // either outcome means the tamper was caught.
        if let Ok(tampered) = Proof::<Bls12_381>::deserialize_compressed(&bytes[..]) {
            assert!(!verify(&hash, &sender_binding(ALICE), &tampered, &vk))
        }
    }

    #[test]
    fn credential_leaf_and_scoped_sub_are_deterministic() {
        let params = poseidon_params();
        let secret = Fr::from(42u64);
        let commitment = CRH::<Fr>::evaluate(&params, vec![secret]).unwrap();
        let opening = CredentialOpening {
            kyc: true,
            aml: true,
            accredited: false,
            birth_date_days: 8000,
            country_code: *b"CH",
            membership_root: Fr::from(7u64),
            expiry_days: 30000,
            salt: Fr::from(81u64),
        };
        let leaf = credential_leaf(&params, commitment, &opening);
        assert_eq!(leaf, credential_leaf(&params, commitment, &opening));
        assert_ne!(
            leaf,
            credential_leaf(
                &params,
                commitment,
                &CredentialOpening {
                    salt: Fr::from(82u64),
                    ..opening
                }
            )
        );
        let a = asker_scope(&params, "account-a");
        let b = asker_scope(&params, "account-b");
        assert_eq!(
            derive_sub(&params, secret, a),
            derive_sub(&params, secret, a)
        );
        assert_ne!(
            derive_sub(&params, secret, a),
            derive_sub(&params, secret, b)
        );
    }

    #[test]
    fn seed_restoration_recovers_secret_and_scoped_sub() {
        let params = poseidon_params();
        let secret = derive_id_secret(&[4u8; 32]);
        assert_eq!(secret, derive_id_secret(&[4u8; 32]));
        assert_ne!(secret, derive_id_secret(&[5u8; 32]));
        let scope = asker_scope(&params, "acct_1");
        assert_eq!(
            derive_sub(&params, secret, scope),
            derive_sub(&params, derive_id_secret(&[4u8; 32]), scope)
        );
    }

    #[test]
    fn plain_sign_in_binds_nonce_scope_and_secret() {
        let mut rng = test_rng();
        let (pk, vk) = setup_sign_in(&mut rng);
        let params = poseidon_params();
        let secret = Fr::from(42u64);
        let scope = asker_scope(&params, "first-asker");
        let other_scope = asker_scope(&params, "second-asker");
        let nonce = Fr::from(177u64);
        let sub = derive_sub(&params, secret, scope);
        let proof = prove_sign_in(secret, scope, nonce, &pk, &mut rng);
        assert!(verify_sign_in(sub, scope, nonce, &proof, &vk));
        assert!(!verify_sign_in(
            sub,
            scope,
            nonce + Fr::from(1u64),
            &proof,
            &vk
        ));
        assert!(!verify_sign_in(sub, other_scope, nonce, &proof, &vk));
        assert!(!verify_sign_in(
            derive_sub(&params, Fr::from(43u64), scope),
            scope,
            nonce,
            &proof,
            &vk
        ));
        let checked_in =
            VerifyingKey::<Bls12_381>::deserialize_compressed(SIGN_IN_VK_BYTES).unwrap();
        let checked_in_pk = ProvingKey::<Bls12_381>::deserialize_compressed(
            include_bytes!("../sign_in_pk.bin").as_slice(),
        )
        .unwrap();
        let checked_in_proof = prove_sign_in(secret, scope, nonce, &checked_in_pk, &mut rng);
        assert!(verify_sign_in(
            sub,
            scope,
            nonce,
            &checked_in_proof,
            &checked_in
        ));
    }

    #[test]
    fn zeroing_revoked_leaf_invalidates_its_old_membership_path() {
        let params = poseidon_params();
        let mut leaves = vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)];
        let tree = AttestedTree::from_leaves(&params, &leaves).unwrap();
        let path = tree.path(1).unwrap();
        assert_eq!(root_from_path(&params, leaves[1], 1, &path), tree.root());
        leaves[1] = Fr::from(0u64);
        let after_revoke = AttestedTree::from_leaves(&params, &leaves).unwrap();
        let mut incremental = tree.clone();
        incremental
            .replace_leaf(&params, 1, Fr::from(0u64))
            .unwrap();
        assert_eq!(incremental.root(), after_revoke.root());
        assert_eq!(incremental.path(0), after_revoke.path(0));
        assert_ne!(tree.root(), after_revoke.root());
        assert_ne!(
            root_from_path(&params, Fr::from(8u64), 1, &path),
            after_revoke.root()
        );
    }
}
