// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Narrow C ABI for the iOS app. JSON is an envelope for versioning; secrets
//! and proof generation stay in this on-device library, never on a node.

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circuit_identity_zk::{self as zk, predicate};
use serde::Deserialize;
use std::ffi::{CStr, CString, c_char};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Decompressing a proving key takes seconds on a phone, so each is done once
/// per process. `None` means the bundled bytes are corrupt.
fn sign_in_key() -> Option<&'static zk::ProvingKey<Bls12_381>> {
    static KEY: OnceLock<Option<zk::ProvingKey<Bls12_381>>> = OnceLock::new();
    KEY.get_or_init(|| {
        zk::ProvingKey::deserialize_compressed(
            include_bytes!("../../../circuits/identity-zk/sign_in_pk.bin").as_slice(),
        )
        .ok()
    })
    .as_ref()
}

fn predicate_key() -> Option<&'static zk::ProvingKey<Bls12_381>> {
    static KEY: OnceLock<Option<zk::ProvingKey<Bls12_381>>> = OnceLock::new();
    KEY.get_or_init(|| {
        zk::ProvingKey::deserialize_compressed(
            include_bytes!("../../../circuits/identity-zk/predicate_pk.bin").as_slice(),
        )
        .ok()
    })
    .as_ref()
}

#[derive(Deserialize)]
struct Opening {
    kyc: bool,
    aml: bool,
    accredited: bool,
    birth_date_days: u32,
    country_code: String,
    membership_root: String,
    expiry_days: u32,
    salt: String,
    id_commitment: Option<String>,
    leaf: Option<String>,
}

#[derive(Deserialize)]
struct Context {
    scope: String,
    nonce: String,
    claims_mask: u32,
    age_n: u32,
    country_set_hash: String,
    group_root: String,
    merkle_root: String,
    today_days: u32,
    age_cutoff_days: u32,
}

/// A regulated asset's gate, as the node returns it (`required_claims` in
/// `ClaimTopic` names, any case: `Kyc`, `Aml`, `Accredited`, `Jurisdiction`).
#[derive(Deserialize)]
struct AssetGate {
    asset_ref: String,
    required_claims: Vec<String>,
    allowed_jurisdictions: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Request {
    operation: String,
    seed_hex: String,
    context: Option<Context>,
    opening: Option<Opening>,
    leaves: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    membership_path: Option<Vec<String>>,
    membership_index: Option<u32>,
    /// `prove_asset_claim` only.
    asset: Option<AssetGate>,
    sender_pubkey: Option<String>,
    today_days: Option<u32>,
}

fn parse_field(hex_value: &str) -> Result<Fr, String> {
    let bytes = hex::decode(hex_value).map_err(|_| "invalid field hex")?;
    if bytes.len() != 32 {
        return Err("field must be 32 bytes".into());
    }
    Fr::deserialize_compressed(bytes.as_slice()).map_err(|_| "noncanonical field".into())
}

fn encode_field(value: &Fr) -> String {
    let mut out = Vec::new();
    value
        .serialize_compressed(&mut out)
        .expect("field serialization");
    hex::encode(out)
}

/// Parsing an off-chain QR is not trusting its attestor: the holder checks
/// the opening against a live on-chain leaf before generating a claim proof.
fn validate_opening(input: Opening, secret: Fr) -> Result<(zk::CredentialOpening, Fr), String> {
    if !zk::valid_country_code(&input.country_code) {
        return Err("invalid country code".into());
    }
    let bytes = input.country_code.as_bytes();
    let params = zk::poseidon_params();
    let commitment = zk::id_commitment(&params, secret);
    if let Some(expected) = &input.id_commitment {
        if parse_field(expected)? != commitment {
            return Err("opening is for another wallet".into());
        }
    }
    let opening = zk::CredentialOpening {
        kyc: input.kyc,
        aml: input.aml,
        accredited: input.accredited,
        birth_date_days: input.birth_date_days,
        country_code: [bytes[0], bytes[1]],
        membership_root: parse_field(&input.membership_root)?,
        expiry_days: input.expiry_days,
        salt: parse_field(&input.salt)?,
    };
    let leaf = zk::credential_leaf(&params, commitment, &opening);
    if let Some(expected) = &input.leaf {
        if parse_field(expected)? != leaf {
            return Err("credential leaf does not match its opening".into());
        }
    }
    Ok((opening, leaf))
}

fn proof_json(mut input: Request) -> Result<serde_json::Value, String> {
    let mut seed = hex::decode(&input.seed_hex).map_err(|_| "invalid wallet seed")?;
    input.seed_hex.zeroize();
    if seed.len() != 32 {
        seed.zeroize();
        return Err("wallet seed must be 32 bytes".into());
    }
    let secret = zk::derive_id_secret(&seed);
    seed.zeroize();
    let params = zk::poseidon_params();
    if input.operation == "derive_id_secret" {
        return Ok(serde_json::json!({ "id_secret": encode_field(&secret) }));
    }
    if input.operation == "id_commitment" {
        return Ok(serde_json::json!({
            "id_commitment": encode_field(&zk::id_commitment(&params, secret)),
        }));
    }
    if input.operation == "validate_opening" {
        let (_, leaf) = validate_opening(input.opening.ok_or("credential required")?, secret)?;
        return Ok(serde_json::json!({ "leaf": encode_field(&leaf) }));
    }
    if input.operation == "prove_asset_claim" {
        return prove_asset_claim(input, secret);
    }
    let context = input.context.ok_or("missing context")?;
    let scope = parse_field(&context.scope)?;
    let nonce = parse_field(&context.nonce)?;
    let sub = zk::derive_sub(&params, secret, scope);
    if input.operation == "derive_sub" {
        return Ok(serde_json::json!({ "sub": encode_field(&sub) }));
    }
    if input.operation != "prove" {
        return Err("unknown operation".into());
    }
    let mut rng = ark_std::rand::rngs::OsRng;
    let proof = if context.claims_mask == 0 {
        let pk = sign_in_key().ok_or("invalid bundled sign-in key")?;
        zk::prove_sign_in(secret, scope, nonce, pk, &mut rng)
    } else {
        if context.claims_mask > 63 {
            return Err("invalid claim mask".into());
        }
        let (opening, leaf) =
            validate_opening(input.opening.ok_or("credential required")?, secret)?;
        let leaves = input
            .leaves
            .ok_or("leaf list required")?
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_index = leaves
            .iter()
            .position(|value| *value == leaf)
            .ok_or("credential is not in the live set")?;
        let tree = zk::AttestedTree::from_leaves(&params, &leaves).ok_or("too many leaves")?;
        let public = predicate::Public {
            sub,
            scope,
            nonce,
            claims_mask: context.claims_mask,
            age_n: context.age_n,
            country_set_hash: parse_field(&context.country_set_hash)?,
            group_root: parse_field(&context.group_root)?,
            merkle_root: parse_field(&context.merkle_root)?,
            today_days: context.today_days,
            age_cutoff_days: context.age_cutoff_days,
        };
        if tree.root() != public.merkle_root {
            return Err("leaf list root changed; retry".into());
        }
        // The request's allowed countries, as the tree `country_set_hash`
        // commits to. Only needed (and only checked) when residency is asked.
        let (country_path, country_index) = if context.claims_mask & predicate::RESIDENCY != 0 {
            let requested = input.countries.unwrap_or_default();
            let countries = predicate::country_set(requested.iter().map(String::as_str))
                .ok_or("invalid country")?;
            if predicate::country_set_hash(&params, &countries) != public.country_set_hash {
                return Err("country list does not match the request".into());
            }
            predicate::country_path(
                &params,
                &countries,
                u16::from_be_bytes(opening.country_code),
            )
            .ok_or("claim not satisfied")?
        } else {
            ([Fr::from(0u64); predicate::COUNTRY_TREE_DEPTH], 0)
        };
        let member = input.membership_path.unwrap_or_default();
        let mut membership_path = [Fr::from(0u64); zk::ATTESTED_TREE_DEPTH];
        if context.claims_mask & predicate::MEMBERSHIP != 0
            && member.len() != zk::ATTESTED_TREE_DEPTH
        {
            return Err("membership path required".into());
        }
        for (i, s) in member.iter().enumerate() {
            if i >= zk::ATTESTED_TREE_DEPTH {
                return Err("membership path too long".into());
            }
            membership_path[i] = parse_field(s)?;
        }
        let witness = predicate::Witness {
            id_secret: secret,
            opening,
            leaf_path: tree.path(leaf_index).ok_or("missing leaf")?,
            leaf_index: leaf_index as u32,
            membership_path,
            membership_index: input.membership_index.unwrap_or(0),
            country_path,
            country_index,
        };
        let pk = predicate_key().ok_or("invalid bundled predicate key")?;
        predicate::prove_predicate(public, witness, pk, &mut rng)
            .map_err(|_| "claim not satisfied")?
    };
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|_| "proof serialization")?;
    Ok(serde_json::json!({ "sub": encode_field(&sub), "proof": hex::encode(bytes) }))
}

/// `VerifyClaimProof` (payload variant 40) for a private-mode asset: proves
/// the imported credential meets the asset's gate without revealing it.
/// Pass the account's on-chain `identity_hash` as `opening.leaf`, so a
/// credential that isn't the attested one fails here, not on chain.
/// `today_days` defaults to the current UTC day, which the chain requires
/// within a day of the block.
fn prove_asset_claim(input: Request, secret: Fr) -> Result<serde_json::Value, String> {
    let (opening, _) = validate_opening(input.opening.ok_or("credential required")?, secret)?;
    let gate = input.asset.ok_or("asset required")?;
    let sender = hex::decode(input.sender_pubkey.ok_or("sender_pubkey required")?)
        .map_err(|_| "invalid sender_pubkey")?;
    if sender.len() != 32 {
        return Err("sender_pubkey must be 32 bytes".into());
    }
    // Same mapping as `circuit_identity::verify_claim_proof`; `Jurisdiction`
    // needs no bit of its own, the allowed list restricts it.
    let mut mask = 0;
    for topic in &gate.required_claims {
        mask |= match topic.to_ascii_lowercase().as_str() {
            "kyc" => predicate::KYC,
            "aml" => predicate::AML,
            "accredited" => predicate::ACCREDITED,
            "jurisdiction" => 0,
            _ => return Err(format!("unknown claim {topic}")),
        };
    }
    let countries = match &gate.allowed_jurisdictions {
        Some(allowed) => {
            mask |= predicate::RESIDENCY;
            predicate::country_set(allowed.iter().map(String::as_str))
                .ok_or("asset's jurisdiction list is not provable")?
        }
        None => Vec::new(),
    };
    let today_days = match input.today_days {
        Some(day) => day,
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock before 1970")?
                .as_secs();
            u32::try_from(now / 86_400).map_err(|_| "clock out of range")?
                + zk::CREDENTIAL_EPOCH_OFFSET_DAYS
        }
    };
    // Before the key: loading it takes seconds on a phone.
    predicate::check_asset_claim(&opening, mask, &countries, today_days)?;
    let pk = predicate_key().ok_or("invalid bundled predicate key")?;
    let (sub, proof) = predicate::prove_asset_claim(
        secret,
        &opening,
        &sender,
        &gate.asset_ref,
        mask,
        &countries,
        today_days,
        pk,
        &mut ark_std::rand::rngs::OsRng,
    )?;
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|_| "proof serialization")?;
    Ok(serde_json::json!({
        "sub": encode_field(&sub),
        "today_days": today_days,
        "proof": hex::encode(bytes),
    }))
}

/// Returned pointer belongs to the caller until `arx_id_free` is called.
/// Only strings made by this library may be passed to the free function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arx_id_json(request: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        if request.is_null() {
            return Err("null request".to_string());
        }
        // SAFETY: the caller provides a NUL-terminated pointer for this call.
        let raw = unsafe { CStr::from_ptr(request) };
        let input: Request =
            serde_json::from_slice(raw.to_bytes()).map_err(|_| "invalid request JSON")?;
        proof_json(input)
    })
    .unwrap_or_else(|_| Err("proof failed".into()));
    let json = match result {
        Ok(value) => value,
        Err(error) => serde_json::json!({ "error": error }),
    };
    CString::new(json.to_string())
        .expect("JSON contains no NUL")
        .into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arx_id_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        // SAFETY: `pointer` is returned by `CString::into_raw` above.
        drop(unsafe { CString::from_raw(pointer) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(value: serde_json::Value) -> serde_json::Value {
        let request = CString::new(value.to_string()).unwrap();
        // SAFETY: our test owns both C strings and frees only the returned one.
        let reply = unsafe { arx_id_json(request.as_ptr()) };
        let json = unsafe { CStr::from_ptr(reply) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { arx_id_free(reply) };
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn plain_sign_in_round_trips_through_the_same_abi_ios_calls() {
        let params = zk::poseidon_params();
        let scope = zk::asker_scope(&params, "acct_shop");
        let seed = "01".repeat(32);
        let nonce = Fr::from(22u64);
        let context = serde_json::json!({
            "scope": encode_field(&scope), "nonce": encode_field(&nonce),
            "claims_mask": 0, "age_n": 0, "country_set_hash": encode_field(&Fr::from(0u64)),
            "group_root": encode_field(&Fr::from(0u64)), "merkle_root": encode_field(&Fr::from(0u64)),
            "today_days": 20000, "age_cutoff_days": 0,
        });
        let reply =
            call(serde_json::json!({ "operation": "prove", "seed_hex": seed, "context": context }));
        assert!(reply.get("error").is_none(), "{reply}");
        let sub = parse_field(reply["sub"].as_str().unwrap()).unwrap();
        let proof_bytes = hex::decode(reply["proof"].as_str().unwrap()).unwrap();
        let proof = zk::Proof::<Bls12_381>::deserialize_compressed(proof_bytes.as_slice()).unwrap();
        let vk =
            zk::VerifyingKey::<Bls12_381>::deserialize_compressed(zk::SIGN_IN_VK_BYTES).unwrap();
        assert!(zk::verify_sign_in(sub, scope, nonce, &proof, &vk));
        assert_eq!(
            sub,
            zk::derive_sub(&params, zk::derive_id_secret(&[1u8; 32]), scope)
        );
        assert!(!zk::verify_sign_in(
            sub,
            scope,
            Fr::from(23u64),
            &proof,
            &vk
        ));
    }

    #[test]
    fn imported_opening_must_match_wallet_commitment_and_its_leaf() {
        let params = zk::poseidon_params();
        let secret = zk::derive_id_secret(&[1u8; 32]);
        let commitment = zk::id_commitment(&params, secret);
        let opening = zk::CredentialOpening {
            kyc: true,
            aml: false,
            accredited: false,
            birth_date_days: 20_000,
            country_code: *b"CH",
            membership_root: Fr::from(0u64),
            expiry_days: 50_000,
            salt: Fr::from(19u64),
        };
        let leaf = zk::credential_leaf(&params, commitment, &opening);
        let candidate = serde_json::json!({
            "kyc": true, "aml": false, "accredited": false,
            "birth_date_days": opening.birth_date_days, "country_code": "CH",
            "membership_root": encode_field(&opening.membership_root),
            "expiry_days": opening.expiry_days, "salt": encode_field(&opening.salt),
            "id_commitment": encode_field(&commitment), "leaf": encode_field(&leaf),
        });
        let check = |opening| {
            call(serde_json::json!({
                "operation": "validate_opening", "seed_hex": "01".repeat(32), "opening": opening,
            }))
        };
        assert_eq!(check(candidate.clone())["leaf"], encode_field(&leaf));
        let mut wrong = candidate.clone();
        wrong["id_commitment"] = encode_field(&Fr::from(1u64)).into();
        assert_eq!(check(wrong)["error"], "opening is for another wallet");
        let mut wrong = candidate.clone();
        wrong["leaf"] = encode_field(&Fr::from(1u64)).into();
        assert_eq!(
            check(wrong)["error"],
            "credential leaf does not match its opening"
        );
        let mut wrong = candidate;
        wrong["country_code"] = "XX".into();
        assert_eq!(check(wrong)["error"], "invalid country code");
    }

    #[test]
    fn attested_kyc_and_age_proof_round_trips_from_opening_and_leaf_list() {
        let params = zk::poseidon_params();
        let secret = zk::derive_id_secret(&[1u8; 32]);
        let opening = zk::CredentialOpening {
            kyc: true,
            aml: false,
            accredited: false,
            birth_date_days: 8000,
            country_code: *b"CH",
            membership_root: Fr::from(0u64),
            expiry_days: 30000,
            salt: Fr::from(9u64),
        };
        let leaf = zk::credential_leaf(&params, zk::id_commitment(&params, secret), &opening);
        let tree = zk::AttestedTree::from_leaves(&params, &[leaf]).unwrap();
        let scope = zk::asker_scope(&params, "acct_shop");
        let nonce = Fr::from(22u64);
        let p = predicate::Public {
            sub: zk::derive_sub(&params, secret, scope),
            scope,
            nonce,
            claims_mask: predicate::KYC | predicate::AGE,
            age_n: 18,
            country_set_hash: predicate::country_set_hash(&params, &[]),
            group_root: Fr::from(0u64),
            merkle_root: tree.root(),
            today_days: 20000,
            age_cutoff_days: 13000,
        };
        let reply = call(serde_json::json!({
            "operation": "prove", "seed_hex": "01".repeat(32),
            "context": {
                "scope": encode_field(&p.scope), "nonce": encode_field(&p.nonce),
                "claims_mask": p.claims_mask, "age_n": p.age_n,
                "country_set_hash": encode_field(&p.country_set_hash),
                "group_root": encode_field(&p.group_root), "merkle_root": encode_field(&p.merkle_root),
                "today_days": p.today_days, "age_cutoff_days": p.age_cutoff_days,
            },
            "opening": {
                "kyc": true, "aml": false, "accredited": false,
                "birth_date_days": 8000, "country_code": "CH",
                "membership_root": encode_field(&opening.membership_root),
                "expiry_days": 30000, "salt": encode_field(&opening.salt),
            },
            "leaves": [encode_field(&leaf)], "countries": [],
        }));
        assert!(reply.get("error").is_none(), "{reply}");
        let proof_bytes = hex::decode(reply["proof"].as_str().unwrap()).unwrap();
        let proof = zk::Proof::<Bls12_381>::deserialize_compressed(proof_bytes.as_slice()).unwrap();
        let vk =
            zk::VerifyingKey::<Bls12_381>::deserialize_compressed(zk::PREDICATE_VK_BYTES).unwrap();
        assert!(predicate::verify_predicate(p, &proof, &vk));
    }

    /// A credential the chain's `verify_claim_proof` should accept: KYC'd,
    /// Swiss, expiring on day 50 000, for the wallet seeded with 0x01s.
    fn swiss_opening() -> (serde_json::Value, Fr) {
        let params = zk::poseidon_params();
        let commitment = zk::id_commitment(&params, zk::derive_id_secret(&[1u8; 32]));
        let opening = zk::CredentialOpening {
            kyc: true,
            aml: false,
            accredited: false,
            birth_date_days: 30_000,
            country_code: *b"CH",
            membership_root: Fr::from(0u64),
            expiry_days: 50_000,
            salt: Fr::from(19u64),
        };
        let leaf = zk::credential_leaf(&params, commitment, &opening);
        let json = serde_json::json!({
            "kyc": true, "aml": false, "accredited": false,
            "birth_date_days": 30_000, "country_code": "CH",
            "membership_root": encode_field(&opening.membership_root),
            "expiry_days": 50_000, "salt": encode_field(&opening.salt),
            "leaf": encode_field(&leaf),
        });
        (json, leaf)
    }

    /// EEA + CH, KYC required: an allow-list longer than the circuit's old
    /// ten slots.
    fn bond() -> xc_primitives::Asset {
        let issuer = xc_primitives::Address::from_pubkey_bytes(&[7u8; 32]).unwrap();
        let mut asset = xc_primitives::Asset::new("bond", issuer, false);
        asset.required_claims = vec![xc_primitives::ClaimTopic::Kyc];
        asset.allowed_jurisdictions = Some(
            [
                "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR",
                "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO",
                "SE", "SI", "SK",
            ]
            .map(String::from)
            .to_vec(),
        );
        asset.private_claims = true;
        asset
    }

    fn prove_for(asset: &xc_primitives::Asset, opening: serde_json::Value) -> serde_json::Value {
        call(serde_json::json!({
            "operation": "prove_asset_claim", "seed_hex": "01".repeat(32), "opening": opening,
            "asset": {
                "asset_ref": asset.asset_ref.to_string(),
                "required_claims": serde_json::to_value(&asset.required_claims).unwrap(),
                "allowed_jurisdictions": asset.allowed_jurisdictions,
            },
            "sender_pubkey": hex::encode([5u8; 32]), "today_days": 46_290,
        }))
    }

    /// What the wallet sends is exactly what the chain verifies: a proof
    /// from this ABI passes `circuit_identity::verify_claim_proof` for the
    /// sender it was made for, and nobody else.
    #[test]
    fn an_asset_claim_proof_verifies_on_chain() {
        use xc_storage::{AccountUpdates, ArxiumDb};
        let asset = bond();
        let (opening, leaf) = swiss_opening();
        let reply = prove_for(&asset, opening);
        assert!(reply.get("error").is_none(), "{reply}");
        let sub: [u8; 32] = hex::decode(reply["sub"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let proof = hex::decode(reply["proof"].as_str().unwrap()).unwrap();

        let db = ArxiumDb::open(
            &std::env::temp_dir().join(format!("arxium-test-arx-id-ffi-{}", std::process::id())),
        )
        .unwrap();
        let sender = xc_primitives::Address::from_pubkey_bytes(&[5u8; 32]).unwrap();
        let other = xc_primitives::Address::from_pubkey_bytes(&[6u8; 32]).unwrap();
        let attested = xc_primitives::AccountEntry {
            identity_hash: Some(encode_field(&leaf)),
            attested_at: Some(0),
            ..Default::default()
        };
        db.write_batch(&AccountUpdates(std::collections::BTreeMap::from([
            (sender.clone(), attested.clone()),
            (other.clone(), attested),
        ])))
        .unwrap();
        let block_time = u64::from(46_290 - zk::CREDENTIAL_EPOCH_OFFSET_DAYS) * 86_400 + 3_600;
        circuit_identity::verify_claim_proof(
            &db, &sender, &asset, &sub, 46_290, block_time, &proof,
        )
        .expect("the chain accepts the wallet's proof");
        assert!(matches!(
            circuit_identity::verify_claim_proof(
                &db, &other, &asset, &sub, 46_290, block_time, &proof
            ),
            Err(circuit_identity::IdentityError::ProofRejected)
        ));
    }

    /// An unmet gate is named before any proving — the holder learns why,
    /// instead of paying for a transaction the chain rejects.
    #[test]
    fn an_unmet_asset_gate_is_named_without_proving() {
        let (opening, _) = swiss_opening();
        let unmet = |edit: &dyn Fn(&mut serde_json::Value, &mut xc_primitives::Asset)| {
            let (mut opening, mut asset) = (opening.clone(), bond());
            edit(&mut opening, &mut asset);
            opening.as_object_mut().unwrap().remove("leaf");
            prove_for(&asset, opening)["error"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            unmet(&|o, _| o["country_code"] = "US".into()),
            "credential's country is not allowed for this asset"
        );
        assert_eq!(
            unmet(&|o, _| o["kyc"] = false.into()),
            "credential lacks the KYC claim"
        );
        assert_eq!(
            unmet(&|o, _| o["expiry_days"] = 40_000.into()),
            "credential expired"
        );
        assert_eq!(
            unmet(&|_, a| {
                a.required_claims.clear();
                a.allowed_jurisdictions = None;
            }),
            "asset asks for no provable claims"
        );
    }
}
