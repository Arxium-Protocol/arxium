//! Claim proof against a live anonymity root. An extra `age_cutoff_days`
//! public input carries the exact Gregorian date N years before `today_days`;
//! the node must derive it, never trust a wallet-supplied value. A constant
//! N*365 cutoff would incorrectly admit under-age users around leap years.

use super::*;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::{CondSelectGadget, ToBitsGadget};
use ark_r1cs_std::prelude::{UInt16, UInt32};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use std::cmp::Ordering;

pub const KYC: u32 = 1;
pub const AML: u32 = 2;
pub const ACCREDITED: u32 = 4;
pub const AGE: u32 = 8;
pub const RESIDENCY: u32 = 16;
pub const MEMBERSHIP: u32 = 32;

#[derive(Clone, Copy)]
pub struct Public {
    pub sub: Fr,
    pub scope: Fr,
    pub nonce: Fr,
    pub claims_mask: u32,
    pub age_n: u32,
    pub country_set_hash: Fr,
    pub group_root: Fr,
    pub merkle_root: Fr,
    pub today_days: u32,
    pub age_cutoff_days: u32,
}

impl Public {
    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            self.sub,
            self.scope,
            self.nonce,
            Fr::from(self.claims_mask),
            Fr::from(self.age_n),
            self.country_set_hash,
            self.group_root,
            self.merkle_root,
            Fr::from(self.today_days),
            Fr::from(self.age_cutoff_days),
        ]
    }
}

#[derive(Clone)]
pub struct Witness {
    pub id_secret: Fr,
    pub opening: CredentialOpening,
    pub leaf_path: [Fr; ATTESTED_TREE_DEPTH],
    pub leaf_index: u32,
    pub membership_path: [Fr; ATTESTED_TREE_DEPTH],
    pub membership_index: u32,
    /// The holder's country's path in the `country_set_hash` tree, and its
    /// leaf index (`country_path`). Unused unless `RESIDENCY` is requested.
    pub country_path: [Fr; COUNTRY_TREE_DEPTH],
    pub country_index: u32,
}

#[derive(Clone)]
pub struct PredicateCircuit {
    pub params: PoseidonConfig<Fr>,
    pub public: Option<Public>,
    pub witness: Option<Witness>,
}

impl ConstraintSynthesizer<Fr> for PredicateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let p = self.public;
        let w = self.witness;
        let input = |value: Option<Fr>| {
            FpVar::new_input(cs.clone(), || {
                value.ok_or(SynthesisError::AssignmentMissing)
            })
        };
        let sub = input(p.map(|p| p.sub))?;
        let scope = input(p.map(|p| p.scope))?;
        let nonce = input(p.map(|p| p.nonce))?;
        let mask = input(p.map(|p| Fr::from(p.claims_mask)))?;
        let age = input(p.map(|p| Fr::from(p.age_n)))?;
        let countries_hash = input(p.map(|p| p.country_set_hash))?;
        let group_root = input(p.map(|p| p.group_root))?;
        let root = input(p.map(|p| p.merkle_root))?;
        let today = input(p.map(|p| Fr::from(p.today_days)))?;
        let cutoff = input(p.map(|p| Fr::from(p.age_cutoff_days)))?;
        let secret = FpVar::new_witness(cs.clone(), || {
            w.as_ref()
                .map(|w| w.id_secret)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nonce_copy = FpVar::new_witness(cs.clone(), || {
            p.map(|p| p.nonce).ok_or(SynthesisError::AssignmentMissing)
        })?;
        nonce_copy.enforce_equal(&nonce)?;

        let flags: Vec<Boolean<Fr>> = (0..6)
            .map(|bit| {
                Boolean::new_witness(cs.clone(), || {
                    p.map(|p| p.claims_mask & (1 << bit) != 0)
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;
        let combined = flags
            .iter()
            .enumerate()
            .fold(FpVar::constant(Fr::from(0u64)), |sum, (i, flag)| {
                sum + FpVar::from(flag.clone()) * Fr::from(1u64 << i)
            });
        combined.enforce_equal(&mask)?;
        let requested = flags.iter().fold(Boolean::FALSE, |acc, flag| &acc | flag);

        let params = CRHParametersVar::new_constant(cs.clone(), self.params)?;
        let id_commitment = CRHGadget::<Fr>::evaluate(&params, &[secret.clone()])?;
        CRHGadget::<Fr>::evaluate(&params, &[secret, scope])?.enforce_equal(&sub)?;
        let opening = w.as_ref().map(|w| &w.opening);
        let flag =
            |f: fn(&CredentialOpening) -> bool| -> ark_relations::gr1cs::Result<Boolean<Fr>> {
                Boolean::new_witness(cs.clone(), || {
                    opening.map(f).ok_or(SynthesisError::AssignmentMissing)
                })
            };
        let kyc = flag(|o| o.kyc)?;
        let aml = flag(|o| o.aml)?;
        let accredited = flag(|o| o.accredited)?;
        for (need, has) in [
            (&flags[0], &kyc),
            (&flags[1], &aml),
            (&flags[2], &accredited),
        ] {
            (need & &!has).enforce_equal(&Boolean::FALSE)?;
        }
        let birth_bits = UInt32::<Fr>::new_witness(cs.clone(), || {
            opening
                .map(|o| o.birth_date_days)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let expiry_bits = UInt32::<Fr>::new_witness(cs.clone(), || {
            opening
                .map(|o| o.expiry_days)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let country_bits = UInt16::<Fr>::new_witness(cs.clone(), || {
            opening
                .map(|o| u16::from_be_bytes(o.country_code))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let birth = Boolean::le_bits_to_fp(&birth_bits.to_bits_le()?)?;
        let expiry = Boolean::le_bits_to_fp(&expiry_bits.to_bits_le()?)?;
        let country = Boolean::le_bits_to_fp(&country_bits.to_bits_le()?)?;
        let membership_root = FpVar::new_witness(cs.clone(), || {
            opening
                .map(|o| o.membership_root)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let salt = FpVar::new_witness(cs.clone(), || {
            opening
                .map(|o| o.salt)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let leaf = CRHGadget::<Fr>::evaluate(
            &params,
            &[
                FpVar::constant(Fr::from(1u64)),
                id_commitment.clone(),
                FpVar::from(kyc),
                FpVar::from(aml),
                FpVar::from(accredited),
                birth.clone(),
                country.clone(),
                membership_root.clone(),
                expiry.clone(),
                salt,
            ],
        )?;

        let path = w.as_ref().map(|w| &w.leaf_path);
        let index = w.as_ref().map(|w| w.leaf_index);
        let computed = merkle_gadget(cs.clone(), &params, leaf, path, index)?;
        ((computed - root) * FpVar::from(requested.clone())).enforce_equal(&FpVar::zero())?;

        let live = expiry.is_cmp(&today, Ordering::Greater, true)?;
        (&requested & &!live).enforce_equal(&Boolean::FALSE)?;
        let mut age_valid = Boolean::FALSE;
        for n in [13, 16, 18, 21] {
            age_valid = &age_valid | &age.is_eq(&FpVar::constant(Fr::from(n)))?;
        }
        (&flags[3] & &!age_valid).enforce_equal(&Boolean::FALSE)?;
        let old_enough = birth.is_cmp(&cutoff, Ordering::Less, true)?;
        (&flags[3] & &!old_enough).enforce_equal(&Boolean::FALSE)?;

        // Residency: the credential's country is a leaf of the allowed-set
        // tree. Its padding leaves are zero, so a zero (absent) country must
        // never match — the check zkPassport makes against its padding.
        let path = w.as_ref().map(|w| &w.country_path);
        let index = w.as_ref().map(|w| w.country_index);
        let computed_countries = merkle_gadget(cs.clone(), &params, country.clone(), path, index)?;
        ((computed_countries - countries_hash) * FpVar::from(flags[4].clone()))
            .enforce_equal(&FpVar::zero())?;
        (&flags[4] & &country.is_eq(&FpVar::zero())?).enforce_equal(&Boolean::FALSE)?;

        ((membership_root - &group_root) * FpVar::from(flags[5].clone()))
            .enforce_equal(&FpVar::zero())?;
        let member_path = w.as_ref().map(|w| &w.membership_path);
        let member_index = w.as_ref().map(|w| w.membership_index);
        let computed_group = merkle_gadget(cs, &params, id_commitment, member_path, member_index)?;
        ((computed_group - group_root) * FpVar::from(flags[5].clone()))
            .enforce_equal(&FpVar::zero())
    }
}

fn merkle_gadget<const DEPTH: usize>(
    cs: ConstraintSystemRef<Fr>,
    params: &CRHParametersVar<Fr>,
    mut node: FpVar<Fr>,
    path: Option<&[Fr; DEPTH]>,
    index: Option<u32>,
) -> ark_relations::gr1cs::Result<FpVar<Fr>> {
    for depth in 0..DEPTH {
        let sibling = FpVar::new_witness(cs.clone(), || {
            path.map(|p| p[depth])
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let right = Boolean::new_witness(cs.clone(), || {
            index
                .map(|i| i & (1 << depth) != 0)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let left = FpVar::conditionally_select(&right, &sibling, &node)?;
        let right_node = FpVar::conditionally_select(&right, &node, &sibling)?;
        node = CRHGadget::<Fr>::evaluate(params, &[left, right_node])?;
    }
    Ok(node)
}

/// Depth of the allowed-country tree: 256 leaves, room for every ISO 3166-1
/// alpha-2 code (249), so no allow-list is ever too long to prove. Same
/// approach as zkPassport's all-countries list, as a Merkle root instead of a
/// flat hash: 8 Poseidon hashes in-circuit instead of ~125.
pub const COUNTRY_TREE_DEPTH: usize = 8;

/// Canonical allowed-country set: codes as big-endian `u16`, sorted and
/// deduplicated — the leaf order of the `country_set_hash` tree, so node and
/// wallet always build the same one. `None` for an invalid code or an empty
/// set.
pub fn country_set<'a>(codes: impl IntoIterator<Item = &'a str>) -> Option<Vec<u16>> {
    let set = codes
        .into_iter()
        .map(|code| {
            valid_country_code(code)
                .then(|| u16::from_be_bytes([code.as_bytes()[0], code.as_bytes()[1]]))
        })
        .collect::<Option<std::collections::BTreeSet<u16>>>()?;
    (!set.is_empty()).then(|| set.into_iter().collect())
}

fn country_tree(params: &PoseidonConfig<Fr>, countries: &[u16]) -> Vec<Vec<Fr>> {
    let mut level: Vec<Fr> = (0..1usize << COUNTRY_TREE_DEPTH)
        .map(|i| Fr::from(countries.get(i).copied().unwrap_or(0)))
        .collect();
    let mut levels = vec![level.clone()];
    for _ in 0..COUNTRY_TREE_DEPTH {
        level = level
            .chunks(2)
            .map(|pair| poseidon_pair(params, pair[0], pair[1]))
            .collect();
        levels.push(level.clone());
    }
    levels
}

/// The `country_set_hash` public input: the root of a depth-8 Poseidon tree
/// over `country_set`'s output, zero-padded. An empty set gives the
/// all-padding root, which no country can open (the circuit rejects zero).
pub fn country_set_hash(params: &PoseidonConfig<Fr>, countries: &[u16]) -> Fr {
    country_tree(params, countries)[COUNTRY_TREE_DEPTH][0]
}

/// The witness for `RESIDENCY`: `country`'s sibling path and leaf index in
/// `countries`' tree, or `None` if it isn't in the set.
pub fn country_path(
    params: &PoseidonConfig<Fr>,
    countries: &[u16],
    country: u16,
) -> Option<([Fr; COUNTRY_TREE_DEPTH], u32)> {
    let index = countries
        .iter()
        .position(|c| *c == country && country != 0)?;
    let levels = country_tree(params, countries);
    let path = std::array::from_fn(|depth| levels[depth][(index >> depth) ^ 1]);
    Some((path, index as u32))
}

/// The public inputs of an on-chain claim proof (`VerifyClaimProof`). The
/// one place they are built, for the chain's verifier and the wallet's
/// prover alike, so the two can't drift apart:
/// - `merkle_root` is a one-leaf tree over the holder's own credential leaf
///   (the account's `identity_hash`): the proof speaks for that account.
/// - `scope` is the asset and `nonce` the sender's key, so a proof can't be
///   moved to another asset or replayed by another sender.
/// - Age and membership are never asked on chain; their inputs are zero.
#[allow(clippy::too_many_arguments)]
pub fn asset_claim_public(
    params: &PoseidonConfig<Fr>,
    leaf: Fr,
    sender_pubkey: &[u8],
    asset_ref: &str,
    claims_mask: u32,
    countries: &[u16],
    sub: Fr,
    today_days: u32,
) -> Public {
    Public {
        sub,
        scope: asset_scope(params, asset_ref),
        nonce: sender_binding(sender_pubkey),
        claims_mask,
        age_n: 0,
        country_set_hash: country_set_hash(params, countries),
        group_root: Fr::from(0u64),
        merkle_root: AttestedTree::from_leaves(params, &[leaf])
            .expect("one leaf fits the tree")
            .root(),
        today_days,
        age_cutoff_days: 0,
    }
}

/// Whether `opening` meets an asset's gate as of `today_days`, with the
/// unmet claim named. Cheap, so a wallet can say why before it loads the
/// proving key; `prove_asset_claim` runs it too.
pub fn check_asset_claim(
    opening: &CredentialOpening,
    claims_mask: u32,
    countries: &[u16],
    today_days: u32,
) -> Result<(), String> {
    if claims_mask == 0 || claims_mask & !(KYC | AML | ACCREDITED | RESIDENCY) != 0 {
        return Err("asset asks for no provable claims".into());
    }
    for (bit, held, name) in [
        (KYC, opening.kyc, "KYC"),
        (AML, opening.aml, "AML"),
        (ACCREDITED, opening.accredited, "accredited-investor"),
    ] {
        if claims_mask & bit != 0 && !held {
            return Err(format!("credential lacks the {name} claim"));
        }
    }
    if opening.expiry_days <= today_days {
        return Err("credential expired".into());
    }
    let country = u16::from_be_bytes(opening.country_code);
    if claims_mask & RESIDENCY != 0 && (country == 0 || !countries.contains(&country)) {
        return Err("credential's country is not allowed for this asset".into());
    }
    Ok(())
}

/// The wallet side of `VerifyClaimProof`: proves that the credential
/// `opening` (for `id_secret`) meets `claims_mask` over `countries`, for
/// `asset_ref`, sent by `sender_pubkey`, dated `today_days`. Returns `sub`
/// and the proof. An unmet claim is reported by name instead of producing a
/// proof the chain would only reject.
#[allow(clippy::too_many_arguments)]
pub fn prove_asset_claim<R: RngCore + ark_std::rand::CryptoRng>(
    id_secret: Fr,
    opening: &CredentialOpening,
    sender_pubkey: &[u8],
    asset_ref: &str,
    claims_mask: u32,
    countries: &[u16],
    today_days: u32,
    pk: &ProvingKey<Bls12_381>,
    rng: &mut R,
) -> Result<(Fr, Proof<Bls12_381>), String> {
    check_asset_claim(opening, claims_mask, countries, today_days)?;
    let params = poseidon_params();
    let (country_path, country_index) = if claims_mask & RESIDENCY != 0 {
        self::country_path(&params, countries, u16::from_be_bytes(opening.country_code))
            .ok_or("credential's country is not allowed for this asset")?
    } else {
        ([Fr::from(0u64); COUNTRY_TREE_DEPTH], 0)
    };
    let leaf = credential_leaf(&params, id_commitment(&params, id_secret), opening);
    let scope = asset_scope(&params, asset_ref);
    let sub = derive_sub(&params, id_secret, scope);
    let public = asset_claim_public(
        &params,
        leaf,
        sender_pubkey,
        asset_ref,
        claims_mask,
        countries,
        sub,
        today_days,
    );
    let witness = Witness {
        id_secret,
        opening: opening.clone(),
        leaf_path: AttestedTree::from_leaves(&params, &[leaf])
            .expect("one leaf fits the tree")
            .path(0)
            .expect("leaf 0 exists"),
        leaf_index: 0,
        membership_path: [Fr::from(0u64); ATTESTED_TREE_DEPTH],
        membership_index: 0,
        country_path,
        country_index,
    };
    let proof = prove_predicate(public, witness, pk, rng).map_err(|_| "claim not satisfied")?;
    Ok((sub, proof))
}

pub fn setup_predicate<R: RngCore + ark_std::rand::CryptoRng>(
    rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(
        PredicateCircuit {
            params: poseidon_params(),
            public: None,
            witness: None,
        },
        rng,
    )
    .expect("predicate setup")
}

pub fn prove_predicate<R: RngCore + ark_std::rand::CryptoRng>(
    public: Public,
    witness: Witness,
    pk: &ProvingKey<Bls12_381>,
    rng: &mut R,
) -> Result<Proof<Bls12_381>, SynthesisError> {
    ark_groth16::Groth16::<Bls12_381>::prove(
        pk,
        PredicateCircuit {
            params: poseidon_params(),
            public: Some(public),
            witness: Some(witness),
        },
        rng,
    )
}

pub fn verify_predicate(
    public: Public,
    proof: &Proof<Bls12_381>,
    vk: &VerifyingKey<Bls12_381>,
) -> bool {
    ark_groth16::Groth16::<Bls12_381>::verify(vk, &public.inputs(), proof).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn fixture() -> (Public, Witness) {
        let params = poseidon_params();
        let secret = Fr::from(123u64);
        let commitment = CRH::<Fr>::evaluate(&params, vec![secret]).unwrap();
        let group = AttestedTree::from_leaves(&params, &[commitment]).unwrap();
        let opening = CredentialOpening {
            kyc: true,
            aml: true,
            accredited: true,
            birth_date_days: 8000,
            country_code: *b"CH",
            membership_root: group.root(),
            expiry_days: 30000,
            salt: Fr::from(55u64),
        };
        let leaf = credential_leaf(&params, commitment, &opening);
        let live = AttestedTree::from_leaves(&params, &[leaf]).unwrap();
        // EEA + CH: 31 countries, three times the old ten-slot limit, with
        // CH somewhere in the middle of the tree rather than at leaf 0.
        let countries = country_set(EEA_AND_CH).unwrap();
        let (country_path, country_index) =
            super::country_path(&params, &countries, u16::from_be_bytes(*b"CH")).unwrap();
        let scope = asker_scope(&params, "acct_shop");
        let p = Public {
            sub: derive_sub(&params, secret, scope),
            scope,
            nonce: Fr::from(17u64),
            claims_mask: 0,
            age_n: 18,
            country_set_hash: country_set_hash(&params, &countries),
            group_root: group.root(),
            merkle_root: live.root(),
            today_days: 20000,
            age_cutoff_days: 13000,
        };
        let w = Witness {
            id_secret: secret,
            opening,
            leaf_path: live.path(0).unwrap(),
            leaf_index: 0,
            membership_path: group.path(0).unwrap(),
            membership_index: 0,
            country_path,
            country_index,
        };
        (p, w)
    }

    const EEA_AND_CH: [&str; 31] = [
        "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU",
        "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI",
        "SK",
    ];

    /// Any allow-list size fits, a country outside it can't borrow another
    /// country's path, and an empty country can't open a padding leaf.
    #[test]
    fn residency_proves_membership_of_a_list_of_any_length() {
        let params = poseidon_params();
        let every: Vec<&str> = ISO3166_ALPHA2.split_ascii_whitespace().collect();
        let all = country_set(every.iter().copied()).unwrap();
        assert_eq!(all.len(), 249);
        let (mut p, mut w) = fixture();
        p.claims_mask = RESIDENCY;
        p.country_set_hash = country_set_hash(&params, &all);
        (w.country_path, w.country_index) =
            country_path(&params, &all, u16::from_be_bytes(*b"CH")).unwrap();
        assert!(satisfies(p, w).0, "CH within all 249 ISO codes");

        let (mut p, mut w) = fixture();
        p.claims_mask = RESIDENCY;
        w.opening.country_code = *b"US";
        assert!(!satisfies(p, w.clone()).0, "US reusing CH's path");
        w.opening.country_code = [0, 0];
        let padding = countries_padding_path(&params);
        (w.country_path, w.country_index) = padding;
        assert!(
            !satisfies(p, w).0,
            "an empty country opening a zero padding leaf"
        );
    }

    /// The path of the first zero padding leaf in the fixture's set — what a
    /// credential with no country would try to use.
    fn countries_padding_path(params: &PoseidonConfig<Fr>) -> ([Fr; COUNTRY_TREE_DEPTH], u32) {
        let countries = country_set(EEA_AND_CH).unwrap();
        let index = countries.len();
        let levels = country_tree(params, &countries);
        (
            std::array::from_fn(|depth| levels[depth][(index >> depth) ^ 1]),
            index as u32,
        )
    }

    fn satisfies(p: Public, w: Witness) -> (bool, usize) {
        let cs = ConstraintSystem::new_ref();
        PredicateCircuit {
            params: poseidon_params(),
            public: Some(p),
            witness: Some(w),
        }
        .generate_constraints(cs.clone())
        .unwrap();
        (cs.is_satisfied().unwrap(), cs.num_constraints())
    }

    #[test]
    fn each_claim_is_constrained() {
        for mask in [
            KYC,
            AML,
            ACCREDITED,
            AGE,
            RESIDENCY,
            MEMBERSHIP,
            KYC | AGE | RESIDENCY | MEMBERSHIP,
        ] {
            let (mut p, w) = fixture();
            p.claims_mask = mask;
            let (valid, count) = satisfies(p, w.clone());
            assert!(valid, "mask={mask}");
            assert!(count < 30_000, "{count} constraints");
            if mask == KYC | AGE | RESIDENCY | MEMBERSHIP {
                eprintln!("predicate circuit: {count} constraints");
            }
            let mut wrong = w;
            if mask & KYC != 0 {
                wrong.opening.kyc = false;
            } else if mask & AML != 0 {
                wrong.opening.aml = false;
            } else if mask & ACCREDITED != 0 {
                wrong.opening.accredited = false;
            } else if mask & AGE != 0 {
                wrong.opening.birth_date_days = 15000;
            } else if mask & RESIDENCY != 0 {
                wrong.opening.country_code = *b"DE";
            } else {
                wrong.membership_path[0] += Fr::from(1u64);
            }
            assert!(
                !satisfies(p, wrong).0,
                "mask={mask} must reject a bad witness"
            );
        }
        let (mut p, mut w) = fixture();
        p.claims_mask = KYC;
        w.opening.expiry_days = 100;
        assert!(!satisfies(p, w).0, "expired credential");
        let (mut p, w) = fixture();
        p.claims_mask = KYC;
        p.scope = asker_scope(&poseidon_params(), "acct_other");
        assert!(!satisfies(p, w).0, "other asker's scope");
    }

    #[test]
    fn checked_in_keys_verify_only_the_bound_nonce_scope_root_and_sub() {
        let mut rng = StdRng::seed_from_u64(77);
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed(
            include_bytes!("../predicate_pk.bin").as_slice(),
        )
        .unwrap();
        let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(PREDICATE_VK_BYTES).unwrap();
        let (mut public, witness) = fixture();
        public.claims_mask = KYC | AGE | RESIDENCY | MEMBERSHIP;
        let started = std::time::Instant::now();
        let proof = prove_predicate(public, witness, &pk, &mut rng).unwrap();
        let proving_time = started.elapsed();
        let mut encoded = Vec::new();
        proof.serialize_compressed(&mut encoded).unwrap();
        eprintln!(
            "predicate proof: {} bytes, {} ms on this host",
            encoded.len(),
            proving_time.as_millis()
        );
        assert!(verify_predicate(public, &proof, &vk));
        let mut forged = public;
        forged.nonce += Fr::from(1u64);
        assert!(!verify_predicate(forged, &proof, &vk));
        forged = public;
        forged.scope = asker_scope(&poseidon_params(), "acct_other");
        assert!(!verify_predicate(forged, &proof, &vk));
        forged = public;
        forged.sub += Fr::from(1u64);
        assert!(!verify_predicate(forged, &proof, &vk));
        forged = public;
        forged.merkle_root += Fr::from(1u64);
        assert!(!verify_predicate(forged, &proof, &vk));
    }
}
