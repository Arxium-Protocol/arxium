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
        let mut countries = [0u16; 10];
        for (i, code) in input.countries.unwrap_or_default().into_iter().enumerate() {
            if i >= 10 {
                return Err("too many countries".into());
            }
            let bytes = code.as_bytes();
            if !zk::valid_country_code(&code) {
                return Err("invalid country".into());
            }
            countries[i] = u16::from_be_bytes([bytes[0], bytes[1]]);
        }
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
            countries,
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
        let countries = [0u16; 10];
        let p = predicate::Public {
            sub: zk::derive_sub(&params, secret, scope),
            scope,
            nonce,
            claims_mask: predicate::KYC | predicate::AGE,
            age_n: 18,
            country_set_hash: predicate::country_set_hash(&params, &countries),
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
}
