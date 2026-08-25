// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Toy zk credential-proof circuit: proves knowledge of a preimage `x` such
//! that `Poseidon(x) == credential_hash`, matching
//! `AccountEntry.identity_hash`. Groth16 over BLS12-381 (arkworks), per the
//! whitepaper's Native Identity Architecture — this is one minimal
//! statement, not the full Trust Spectrum.
//!
//! `setup()` runs its own circuit-specific Groth16 parameter generation.
//! **This is not a real trusted-setup ceremony** — the toxic waste (the RNG
//! seed) is not destroyed via multi-party computation, it's just a test RNG
//! in this process. Fine for devnet; replace with a real ceremony before any
//! real credential data flows through this circuit.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::RngCore;

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const ALPHA: u64 = 5;

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

/// Poseidon(preimage) over the scalar field — the value stored as
/// `AccountEntry.identity_hash`.
pub fn credential_hash(params: &PoseidonConfig<Fr>, preimage: &[u8]) -> Fr {
    CRH::<Fr>::evaluate(params, vec![hash_to_field(preimage)]).expect("poseidon evaluate")
}

#[derive(Clone)]
pub struct PreimageCircuit {
    pub params: PoseidonConfig<Fr>,
    pub preimage: Option<Fr>,
    pub credential_hash: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for PreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let hash_var =
            FpVar::new_input(cs.clone(), || self.credential_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let preimage_var =
            FpVar::new_witness(cs.clone(), || self.preimage.ok_or(SynthesisError::AssignmentMissing))?;
        let params_var = CRHParametersVar::new_constant(cs, self.params)?;
        let computed = CRHGadget::<Fr>::evaluate(&params_var, &[preimage_var])?;
        computed.enforce_equal(&hash_var)
    }
}

/// Circuit-specific Groth16 setup. See module docs — devnet only.
pub fn setup<R: RngCore + ark_std::rand::CryptoRng>(
    rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let circuit = PreimageCircuit { params: poseidon_params(), preimage: None, credential_hash: None };
    ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng).expect("groth16 setup")
}

pub fn prove<R: RngCore + ark_std::rand::CryptoRng>(
    preimage: &[u8],
    pk: &ProvingKey<Bls12_381>,
    rng: &mut R,
) -> Proof<Bls12_381> {
    let params = poseidon_params();
    let preimage_fr = hash_to_field(preimage);
    let circuit = PreimageCircuit {
        params: params.clone(),
        preimage: Some(preimage_fr),
        credential_hash: Some(credential_hash(&params, preimage)),
    };
    ark_groth16::Groth16::<Bls12_381>::prove(pk, circuit, rng).expect("groth16 prove")
}

pub fn verify(credential_hash: &Fr, proof: &Proof<Bls12_381>, vk: &VerifyingKey<Bls12_381>) -> bool {
    ark_groth16::Groth16::<Bls12_381>::verify(vk, &[*credential_hash], proof).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn prove_and_verify_roundtrip_with_correct_preimage() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let preimage = b"correct horse battery staple";
        let proof = prove(preimage, &pk, &mut rng);
        let hash = credential_hash(&poseidon_params(), preimage);
        assert!(verify(&hash, &proof, &vk));
    }

    #[test]
    fn verify_rejects_wrong_preimage() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let proof = prove(b"correct horse battery staple", &pk, &mut rng);
        let wrong_hash = credential_hash(&poseidon_params(), b"wrong guess");
        assert!(!verify(&wrong_hash, &proof, &vk));
    }

    #[test]
    fn verify_rejects_tampered_proof_bytes() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng);
        let preimage = b"correct horse battery staple";
        let proof = prove(preimage, &pk, &mut rng);
        let hash = credential_hash(&poseidon_params(), preimage);

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        bytes[0] ^= 0xff;

        // A flipped byte either fails to deserialize into a well-formed
        // proof at all, or deserializes into one that fails verification —
        // either outcome means the tamper was caught.
        match Proof::<Bls12_381>::deserialize_compressed(&bytes[..]) {
            Ok(tampered) => assert!(!verify(&hash, &tampered, &vk)),
            Err(_) => {}
        }
    }
}
