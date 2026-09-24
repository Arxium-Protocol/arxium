// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Scoped sign-in and live-root predicate verification. The gateway rebuilds
//! public inputs from its saved request; callers cannot submit secret claims.

use super::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::OnceLock;

/// A cache of roots observed at chain tips. A removed leaf invalidates *all*
/// earlier roots immediately; retaining those roots for 64 blocks would let
/// a revoked or deregistered credential continue verifying until expiry.
#[derive(Default)]
pub(super) struct IdentityRoots {
    last_leaves: Vec<Fr>,
    history: VecDeque<(u64, Fr)>,
    cached_state_root: Option<String>,
    cached_tree: Option<circuit_identity_zk::AttestedTree>,
}

impl IdentityRoots {
    fn observe(&mut self, height: u64, leaves: &[Fr], root: Fr) {
        let current: HashSet<_> = leaves.iter().copied().collect();
        if self.last_leaves.iter().any(|leaf| !current.contains(leaf)) {
            self.history.clear();
        }
        self.last_leaves = leaves.to_vec();
        self.refresh(height, root);
    }

    fn refresh(&mut self, height: u64, root: Fr) {
        if self
            .history
            .back()
            .is_some_and(|(_, previous)| *previous == root)
        {
            self.history.back_mut().unwrap().0 = height;
        } else {
            self.history.push_back((height, root));
        }
        while self
            .history
            .front()
            .is_some_and(|(at, _)| height.saturating_sub(*at) > 64)
        {
            self.history.pop_front();
        }
    }
}

fn field_hex(value: &Fr) -> String {
    let mut encoded = Vec::new();
    value
        .serialize_compressed(&mut encoded)
        .expect("field serialization");
    hex::encode(encoded)
}

fn live_tree<P: Payload>(state: &AppState<P>) -> Option<(Vec<Fr>, Fr)> {
    // If a block commits while this scan is running, retry on the next
    // request rather than publishing a root made from a mixed snapshot.
    // Hold the root-cache lock across reconciliation so two simultaneous
    // wallet requests cannot install older leaf sets in reverse order.
    let mut cache = state.identity_roots.lock().ok()?;
    let before = state.db.compute_state_root(&[]).ok()?;
    if cache.cached_state_root.as_deref() == Some(&before) {
        let height = state.db.get_tip_height().ok()?.unwrap_or(0);
        let root = cache.cached_tree.as_ref()?.root();
        cache.refresh(height, root);
        return Some((cache.last_leaves.clone(), root));
    }
    let raw: Vec<Fr> = state
        .db
        .live_identity_hashes()
        .ok()?
        .into_iter()
        .map(|hash| {
            // Pre-v1 attestations can be arbitrary opaque strings. Include
            // them in the anonymity set through a separate domain, without
            // making them eligible for the v1 opening relation.
            field(&hash).unwrap_or_else(|| {
                let digest =
                    Sha256::digest([b"arx-id-legacy/v1".as_slice(), hash.as_bytes()].concat());
                circuit_identity_zk::hash_to_field(&digest)
            })
        })
        .collect();
    let mut frequencies = std::collections::HashMap::new();
    for leaf in &raw {
        *frequencies.entry(*leaf).or_insert(0usize) += 1;
    }
    // An identical leaf at two accounts cannot identify which attestation
    // was revoked. Disable both until an attestor reissues distinct salts.
    let leaves: Vec<Fr> = raw
        .into_iter()
        .map(|leaf| {
            if frequencies[&leaf] == 1 {
                leaf
            } else {
                Fr::from(0u64)
            }
        })
        .collect();
    let after = state.db.compute_state_root(&[]).ok()?;
    if before != after {
        return None;
    }
    let params = circuit_identity_zk::poseidon_params();
    let tree = if cache.last_leaves.len() == leaves.len() {
        if let Some(mut tree) = cache.cached_tree.take() {
            for (index, (previous, next)) in cache.last_leaves.iter().zip(&leaves).enumerate() {
                if previous != next {
                    tree.replace_leaf(&params, index, *next)?;
                }
            }
            tree
        } else {
            circuit_identity_zk::AttestedTree::from_leaves(&params, &leaves)?
        }
    } else {
        // New or revoked attestations change the compact ordering. Rebuild
        // once; replacements with unchanged length update only their paths.
        circuit_identity_zk::AttestedTree::from_leaves(&params, &leaves)?
    };
    let root = tree.root();
    let height = state.db.get_tip_height().ok()?.unwrap_or(0);
    cache.observe(height, &leaves, root);
    cache.cached_state_root = Some(after);
    cache.cached_tree = Some(tree);
    Some((leaves, root))
}

pub(super) async fn identity_root<P: Payload>(State(state): State<AppState<P>>) -> Response {
    match live_tree(&state) {
        Some((leaves, root)) => Json(serde_json::json!({
            "root": field_hex(&root), "leaf_count": leaves.len(), "depth": circuit_identity_zk::ATTESTED_TREE_DEPTH,
        })).into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct LeavesQuery {
    cursor: Option<usize>,
}

pub(super) async fn identity_leaves<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<LeavesQuery>,
) -> Response {
    let Some((leaves, root)) = live_tree(&state) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let cursor = query.cursor.unwrap_or(0);
    if cursor > leaves.len() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let end = cursor.saturating_add(1024).min(leaves.len());
    Json(serde_json::json!({
        "root": field_hex(&root),
        "leaves": leaves[cursor..end].iter().map(field_hex).collect::<Vec<_>>(),
        "next_cursor": (end < leaves.len()).then_some(end),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub(super) struct IdentityVerifyRequest {
    sub: String,
    scope: String,
    nonce: String,
    proof: String,
    claims_mask: u32,
    #[serde(default)]
    age_n: u32,
    country_set_hash: Option<String>,
    group_root: Option<String>,
    merkle_root: Option<String>,
    today_days: Option<u32>,
    age_cutoff_days: Option<u32>,
    group: Option<String>,
    group_attestor: Option<String>,
    group_signature: Option<String>,
    group_sequence: Option<u64>,
}

fn valid_group_signature<P: Payload>(
    state: &AppState<P>,
    group: &str,
    root: &str,
    attestor: &str,
    signature: &str,
    sequence: u64,
) -> bool {
    (|| {
        if group.is_empty()
            || group.len() > 64
            || !group
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        field(root)?;
        let address = Address::parse(attestor).ok()?;
        state.db.get_attestor_record(&address).ok()??;
        let public_key: [u8; 32] = address.pubkey_bytes().ok()?.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&public_key).ok()?;
        let bytes: [u8; 64] = hex::decode(signature).ok()?.try_into().ok()?;
        let signature = Signature::from_bytes(&bytes);
        let message = format!("arx-id-group/v1\n{group}\n{root}\n{sequence}");
        Some(key.verify(message.as_bytes(), &signature).is_ok())
    })()
    .unwrap_or(false)
}

#[derive(Deserialize)]
pub(super) struct GroupValidation {
    group: String,
    root: String,
    attestor: String,
    signature: String,
    sequence: u64,
}

pub(super) async fn validate_group<P: Payload>(
    State(state): State<AppState<P>>,
    Json(input): Json<GroupValidation>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "valid": valid_group_signature(
        &state, &input.group, &input.root, &input.attestor, &input.signature, input.sequence,
    ) }))
}

fn field(hex_value: &str) -> Option<Fr> {
    let bytes = hex::decode(hex_value).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Fr::deserialize_compressed(bytes.as_slice()).ok()
}

fn verifying_key() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(
            circuit_identity_zk::SIGN_IN_VK_BYTES,
        )
        .expect("devnet sign-in verifying key")
    })
}

fn predicate_key() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(
            circuit_identity_zk::PREDICATE_VK_BYTES,
        )
        .expect("devnet predicate verifying key")
    })
}

// Gregorian civil date conversion, days since Unix epoch. This pair follows
// the 400-year era arithmetic of Howard Hinnant's civil calendar algorithms.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

fn age_cutoff(today: u32, age: u32) -> Option<u32> {
    let offset = i64::from(circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS);
    let (year, month, day) = civil_from_days(i64::from(today) - offset);
    let earlier = year - i64::from(age);
    let leap = earlier % 4 == 0 && (earlier % 100 != 0 || earlier % 400 == 0);
    let day = if month == 2 && day == 29 && !leap {
        28
    } else {
        day
    };
    u32::try_from(days_from_civil(earlier, month, day) + offset).ok()
}

pub(super) async fn verify_identity<P: Payload>(
    State(state): State<AppState<P>>,
    Json(input): Json<IdentityVerifyRequest>,
) -> Json<serde_json::Value> {
    let valid = if input.claims_mask == 0 {
        verify_payload(&input)
    } else {
        verify_claim_payload(&state, &input)
    };
    Json(serde_json::json!({ "valid": valid }))
}

fn verify_claim_payload<P: Payload>(state: &AppState<P>, input: &IdentityVerifyRequest) -> bool {
    (|| {
        use circuit_identity_zk::predicate::{self, AGE, Public};
        if input.claims_mask > 63 {
            return None;
        }
        let today = input.today_days?;
        let cutoff = input.age_cutoff_days?;
        let current = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs()
            / 86400
            + u64::from(circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS);
        if u64::from(today).abs_diff(current) > 1 {
            return None;
        }
        if input.claims_mask & AGE != 0 {
            if ![13, 16, 18, 21].contains(&input.age_n) || age_cutoff(today, input.age_n)? != cutoff
            {
                return None;
            }
        } else if input.age_n != 0 || cutoff != 0 {
            return None;
        }
        let merkle_root = field(input.merkle_root.as_deref()?)?;
        live_tree(state)?;
        if !state
            .identity_roots
            .lock()
            .ok()?
            .history
            .iter()
            .any(|(_, root)| *root == merkle_root)
        {
            return None;
        }
        let public = Public {
            sub: field(&input.sub)?,
            scope: field(&input.scope)?,
            nonce: field(&input.nonce)?,
            claims_mask: input.claims_mask,
            age_n: input.age_n,
            country_set_hash: field(input.country_set_hash.as_deref()?)?,
            group_root: field(input.group_root.as_deref()?)?,
            merkle_root,
            today_days: today,
            age_cutoff_days: cutoff,
        };
        if input.claims_mask & predicate::MEMBERSHIP != 0 {
            if !valid_group_signature(
                state,
                input.group.as_deref()?,
                input.group_root.as_deref()?,
                input.group_attestor.as_deref()?,
                input.group_signature.as_deref()?,
                input.group_sequence?,
            ) {
                return None;
            }
        }
        let proof_bytes = hex::decode(&input.proof).ok()?;
        let proof =
            circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(proof_bytes.as_slice())
                .ok()?;
        if !predicate::verify_predicate(public, &proof, predicate_key()) {
            return Some(false);
        }
        // A grant can be revoked while Groth16 runs. Reconcile once more at
        // the end and refuse the proof if that invalidated its old root.
        live_tree(state)?;
        if input.claims_mask & predicate::MEMBERSHIP != 0
            && !valid_group_signature(
                state,
                input.group.as_deref()?,
                input.group_root.as_deref()?,
                input.group_attestor.as_deref()?,
                input.group_signature.as_deref()?,
                input.group_sequence?,
            )
        {
            return Some(false);
        }
        Some(
            state
                .identity_roots
                .lock()
                .ok()?
                .history
                .iter()
                .any(|(_, root)| *root == merkle_root),
        )
    })()
    .unwrap_or(false)
}

fn verify_payload(input: &IdentityVerifyRequest) -> bool {
    (|| {
        if input.claims_mask != 0 {
            return None;
        }
        let sub = field(&input.sub)?;
        let scope = field(&input.scope)?;
        let nonce = field(&input.nonce)?;
        let bytes = hex::decode(&input.proof).ok()?;
        let proof =
            circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .ok()?;
        Some(circuit_identity_zk::verify_sign_in(
            sub,
            scope,
            nonce,
            &proof,
            verifying_key(),
        ))
    })()
    .unwrap_or(false)
}

#[derive(Deserialize)]
pub(super) struct ScopeQuery {
    account_id: String,
}

pub(super) async fn identity_scope<P: Payload>(
    State(_state): State<AppState<P>>,
    Query(query): Query<ScopeQuery>,
) -> Json<serde_json::Value> {
    let scope = circuit_identity_zk::asker_scope(
        &circuit_identity_zk::poseidon_params(),
        &query.account_id,
    );
    let mut encoded = Vec::new();
    scope
        .serialize_compressed(&mut encoded)
        .expect("field serialization");
    Json(serde_json::json!({ "scope": hex::encode(encoded) }))
}

#[derive(Deserialize)]
pub(super) struct ContextQuery {
    account_id: String,
    claims: String,
    group_root: Option<String>,
    group_attestor: Option<String>,
    group_signature: Option<String>,
    group_sequence: Option<u64>,
}

/// All values returned here are node-derived. The gateway records them once
/// with the request and passes the exact fields to verification, so a wallet
/// cannot weaken a predicate by replacing its threshold or country set.
pub(super) async fn identity_context<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ContextQuery>,
) -> Response {
    let claims: Vec<String> = match serde_json::from_str(&query.claims) {
        Ok(claims) => claims,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some((mask, age, countries, group)) = parse_claims(&claims) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some((_, root)) = live_tree(&state) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let today = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(time) => {
            (time.as_secs() / 86400) as u32 + circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Some(cutoff) = (if age != 0 {
        age_cutoff(today, age)
    } else {
        Some(0)
    }) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let params = circuit_identity_zk::poseidon_params();
    let scope = circuit_identity_zk::asker_scope(&params, &query.account_id);
    let group_root = if let Some(group) = &group {
        let (Some(root), Some(attestor), Some(signature), Some(sequence)) = (
            query.group_root.as_deref(),
            query.group_attestor.as_deref(),
            query.group_signature.as_deref(),
            query.group_sequence,
        ) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if !valid_group_signature(&state, group, root, attestor, signature, sequence) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        root.to_string()
    } else {
        field_hex(&Fr::from(0u64))
    };
    Json(serde_json::json!({
        "scope": field_hex(&scope), "claims_mask": mask, "age_n": age,
        "country_set_hash": field_hex(&circuit_identity_zk::predicate::country_set_hash(&params, &countries)),
        "group_root": group_root, "merkle_root": field_hex(&root),
        "today_days": today, "age_cutoff_days": cutoff,
    })).into_response()
}

fn parse_claims(claims: &[String]) -> Option<(u32, u32, [u16; 10], Option<String>)> {
    use circuit_identity_zk::predicate::*;
    if claims.len() > 16 {
        return None;
    }
    let mut mask = 0;
    let mut age = 0;
    let mut countries: Option<std::collections::BTreeSet<u16>> = None;
    let mut group: Option<String> = None;
    for claim in claims {
        match claim.as_str() {
            "kyc" => mask |= KYC,
            "aml" => mask |= AML,
            "accredited" => mask |= ACCREDITED,
            value if value.starts_with("age_gte:") => {
                let n = value.strip_prefix("age_gte:")?.parse::<u32>().ok()?;
                if ![13, 16, 18, 21].contains(&n) {
                    return None;
                }
                age = age.max(n);
                mask |= AGE;
            }
            value if value.starts_with("resident_in:") || value.starts_with("resident_in_any:") => {
                let codes: Vec<&str> = if let Some(code) = value.strip_prefix("resident_in:") {
                    vec![code]
                } else {
                    value
                        .strip_prefix("resident_in_any:")?
                        .strip_prefix('[')?
                        .strip_suffix(']')?
                        .split(',')
                        .collect()
                };
                if codes.is_empty() || codes.len() > 10 {
                    return None;
                }
                let set = codes
                    .into_iter()
                    .map(|s| {
                        let bytes = s.as_bytes();
                        if !circuit_identity_zk::valid_country_code(s) {
                            return None;
                        }
                        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                    })
                    .collect::<Option<std::collections::BTreeSet<_>>>()?;
                if set.is_empty() {
                    return None;
                }
                countries = Some(match countries {
                    Some(previous) => previous.intersection(&set).copied().collect(),
                    None => set,
                });
                mask |= RESIDENCY;
            }
            value if value.starts_with("member_of:") => {
                let named = value.strip_prefix("member_of:")?;
                if named.is_empty()
                    || named.len() > 64
                    || !named
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || group.as_deref().is_some_and(|existing| existing != named)
                {
                    return None;
                }
                group = Some(named.to_string());
                mask |= MEMBERSHIP;
            }
            _ => return None,
        }
    }
    let mut fixed = [0u16; 10];
    let chosen = countries.unwrap_or_default();
    if chosen.is_empty() && mask & RESIDENCY != 0 {
        return None;
    }
    for (index, country) in chosen.into_iter().enumerate() {
        fixed[index] = country;
    }
    Some((mask, age, fixed, group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn hex_field(value: &Fr) -> String {
        let mut bytes = Vec::new();
        value.serialize_compressed(&mut bytes).unwrap();
        hex::encode(bytes)
    }

    #[test]
    fn sign_in_refuses_replay_another_scope_and_claim_upgrade() {
        let mut rng = StdRng::seed_from_u64(17);
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(
            include_bytes!("../../../circuits/identity-zk/sign_in_pk.bin").as_slice(),
        )
        .unwrap();
        let params = circuit_identity_zk::poseidon_params();
        let secret = Fr::from(12u64);
        let scope = circuit_identity_zk::asker_scope(&params, "acct_a");
        let nonce = Fr::from(99u64);
        let proof = circuit_identity_zk::prove_sign_in(secret, scope, nonce, &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let mut req = IdentityVerifyRequest {
            sub: hex_field(&circuit_identity_zk::derive_sub(&params, secret, scope)),
            scope: hex_field(&scope),
            nonce: hex_field(&nonce),
            proof: hex::encode(proof_bytes),
            claims_mask: 0,
            age_n: 0,
            country_set_hash: None,
            group_root: None,
            merkle_root: None,
            today_days: None,
            age_cutoff_days: None,
            group: None,
            group_attestor: None,
            group_signature: None,
            group_sequence: None,
        };
        assert!(verify_payload(&req));
        req.claims_mask = 1;
        assert!(!verify_payload(&req));
        req.claims_mask = 0;
        req.nonce = hex_field(&Fr::from(100u64));
        assert!(!verify_payload(&req));
        req.nonce = hex_field(&nonce);
        req.scope = hex_field(&circuit_identity_zk::asker_scope(&params, "acct_b"));
        assert!(!verify_payload(&req));
    }

    #[test]
    fn revocation_and_deregistration_invalidate_older_roots() {
        let mut roots = IdentityRoots::default();
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        roots.observe(1, &[a], Fr::from(11u64));
        roots.observe(2, &[a, b], Fr::from(12u64));
        assert_eq!(roots.history.len(), 2);
        roots.observe(3, &[b], Fr::from(13u64));
        assert_eq!(
            roots.history.len(),
            1,
            "old roots containing revoked a must be discarded"
        );
        roots.observe(4, &[], Fr::from(14u64));
        assert_eq!(
            roots.history.len(),
            1,
            "deregistering b must discard its old root"
        );
    }

    #[test]
    fn gregorian_cutoff_handles_leap_birthdays() {
        let offset = circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS;
        let march_first_2026 = days_from_civil(2026, 3, 1) as u32 + offset;
        assert_eq!(
            age_cutoff(march_first_2026, 18),
            Some(days_from_civil(2008, 3, 1) as u32 + offset)
        );
        let feb_29_2024 = days_from_civil(2024, 2, 29) as u32 + offset;
        assert_eq!(
            civil_from_days(i64::from(feb_29_2024 - offset)),
            (2024, 2, 29)
        );
        assert_eq!(
            age_cutoff(feb_29_2024, 18),
            Some(days_from_civil(2006, 2, 28) as u32 + offset)
        );
    }

    #[test]
    fn catalogue_intersects_country_sets_and_rejects_probing_thresholds() {
        let (mask, age, countries, group) = parse_claims(&[
            "kyc".into(),
            "age_gte:16".into(),
            "age_gte:18".into(),
            "resident_in_any:[CH,DE]".into(),
            "resident_in:CH".into(),
        ])
        .unwrap();
        assert_eq!(mask, 1 | 8 | 16);
        assert_eq!(age, 18);
        assert!(group.is_none());
        assert_eq!(countries[0], u16::from_be_bytes(*b"CH"));
        assert_eq!(countries[1], 0);
        assert!(parse_claims(&["resident_in_any:[CH]".into()]).is_some());
        for invalid in [
            "age_gte:19",
            "resident_in:ch",
            "resident_in:XX",
            "resident_in_any:[CH,DE,FR,IT,ES,PT,AT,NL,BE,LU,SE]",
        ] {
            assert!(parse_claims(&[invalid.into()]).is_none(), "{invalid}");
        }
        let codes: std::collections::HashSet<_> = circuit_identity_zk::ISO3166_ALPHA2
            .split_ascii_whitespace()
            .collect();
        assert_eq!(
            codes.len(),
            249,
            "ISO assignments must be unique and complete"
        );
    }

    #[test]
    fn group_root_requires_a_live_attestors_signature() {
        use ed25519_dalek::{Signer, SigningKey};
        let state = crate::tests::test_state();
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let address = Address::from_pubkey_bytes(signer.verifying_key().as_bytes()).unwrap();
        state
            .db
            .write_batch(&xc_storage::AttestorRegistration {
                attestor: address.clone(),
                record: xc_primitives::AttestorRecord {
                    name: "test".into(),
                    registered_at: 0,
                },
            })
            .unwrap();
        let root = field_hex(&Fr::from(77u64));
        let sig = signer.sign(format!("arx-id-group/v1\nclub\n{root}\n7").as_bytes());
        let hex_sig = hex::encode(sig.to_bytes());
        assert!(valid_group_signature(
            &state,
            "club",
            &root,
            &address.to_string(),
            &hex_sig,
            7,
        ));
        assert!(!valid_group_signature(
            &state,
            "other",
            &root,
            &address.to_string(),
            &hex_sig,
            7,
        ));
        assert!(!valid_group_signature(
            &state,
            "club",
            &root,
            &address.to_string(),
            &hex_sig,
            6,
        ));
        state
            .db
            .write_batch(&xc_storage::AttestorDeregistration(address.clone()))
            .unwrap();
        assert!(!valid_group_signature(
            &state,
            "club",
            &root,
            &address.to_string(),
            &hex_sig,
            7,
        ));
    }

    #[test]
    fn node_verifies_live_claims_and_rejects_revoked_and_deregistered_roots() {
        use circuit_identity_zk::predicate::{self, AGE, KYC};
        let state = crate::tests::test_state();
        let attestor = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let holder = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        state
            .db
            .write_batch(&xc_storage::AttestorRegistration {
                attestor: attestor.clone(),
                record: xc_primitives::AttestorRecord {
                    name: "issuer".into(),
                    registered_at: 0,
                },
            })
            .unwrap();
        let params = circuit_identity_zk::poseidon_params();
        let secret = Fr::from(25u64);
        let today = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 86400) as u32
            + circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS;
        let opening = circuit_identity_zk::CredentialOpening {
            kyc: true,
            aml: false,
            accredited: false,
            birth_date_days: (days_from_civil(1960, 4, 5)
                + i64::from(circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS))
                as u32,
            country_code: *b"CH",
            membership_root: Fr::from(0u64),
            expiry_days: today + 10,
            salt: Fr::from(55u64),
        };
        let leaf = circuit_identity_zk::credential_leaf(
            &params,
            circuit_identity_zk::id_commitment(&params, secret),
            &opening,
        );
        let mut account = xc_primitives::AccountEntry::default();
        account.identity_hash = Some(field_hex(&leaf));
        account.attested_by = Some(attestor.clone());
        state
            .db
            .write_batch(&xc_storage::AccountUpdates(
                std::collections::BTreeMap::from([(holder.clone(), account.clone())]),
            ))
            .unwrap();
        let tree = circuit_identity_zk::AttestedTree::from_leaves(&params, &[leaf]).unwrap();
        let scope = circuit_identity_zk::asker_scope(&params, "acct_shop");
        let country_hash = predicate::country_set_hash(&params, &[0u16; 10]);
        let public = predicate::Public {
            sub: circuit_identity_zk::derive_sub(&params, secret, scope),
            scope,
            nonce: Fr::from(10u64),
            claims_mask: KYC | AGE,
            age_n: 18,
            country_set_hash: country_hash,
            group_root: Fr::from(0u64),
            merkle_root: tree.root(),
            today_days: today,
            age_cutoff_days: age_cutoff(today, 18).unwrap(),
        };
        let witness = predicate::Witness {
            id_secret: secret,
            opening,
            leaf_path: tree.path(0).unwrap(),
            leaf_index: 0,
            membership_path: [Fr::from(0u64); 20],
            membership_index: 0,
            countries: [0; 10],
        };
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(
            include_bytes!("../../../circuits/identity-zk/predicate_pk.bin").as_slice(),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(8);
        let proof = predicate::prove_predicate(public, witness, &pk, &mut rng).unwrap();
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let mut request = IdentityVerifyRequest {
            sub: field_hex(&public.sub),
            scope: field_hex(&scope),
            nonce: field_hex(&public.nonce),
            proof: hex::encode(bytes),
            claims_mask: public.claims_mask,
            age_n: 18,
            country_set_hash: Some(field_hex(&country_hash)),
            group_root: Some(field_hex(&Fr::from(0u64))),
            merkle_root: Some(field_hex(&public.merkle_root)),
            today_days: Some(today),
            age_cutoff_days: Some(public.age_cutoff_days),
            group: None,
            group_attestor: None,
            group_signature: None,
            group_sequence: None,
        };
        assert!(verify_claim_payload(&state, &request));
        request.nonce = field_hex(&Fr::from(11u64));
        assert!(!verify_claim_payload(&state, &request));
        request.nonce = field_hex(&public.nonce);
        account.identity_hash = None;
        state
            .db
            .write_batch(&xc_storage::AccountUpdates(
                std::collections::BTreeMap::from([(holder.clone(), account.clone())]),
            ))
            .unwrap();
        assert!(
            !verify_claim_payload(&state, &request),
            "revocation invalidates old root immediately"
        );
        account.identity_hash = Some(field_hex(&leaf));
        state
            .db
            .write_batch(&xc_storage::AccountUpdates(
                std::collections::BTreeMap::from([(holder, account)]),
            ))
            .unwrap();
        assert!(verify_claim_payload(&state, &request));
        state
            .db
            .write_batch(&xc_storage::AttestorDeregistration(attestor))
            .unwrap();
        assert!(
            !verify_claim_payload(&state, &request),
            "attestor deregistration invalidates the leaf"
        );
    }

    #[test]
    fn legacy_hashes_stay_in_the_set_but_duplicate_leaves_are_unspendable() {
        let state = crate::tests::test_state();
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let legacy = Address::from_pubkey_bytes(&[3u8; 32]).unwrap();
        let leaf = field_hex(&Fr::from(77u64));
        let mut account = xc_primitives::AccountEntry::default();
        account.identity_hash = Some(leaf);
        let mut old = xc_primitives::AccountEntry::default();
        old.identity_hash = Some("pre-v1-opaque-hash".into());
        state
            .db
            .write_batch(&xc_storage::AccountUpdates(
                std::collections::BTreeMap::from([
                    (alice, account.clone()),
                    (bob, account),
                    (legacy, old),
                ]),
            ))
            .unwrap();
        let (leaves, root) = live_tree(&state).unwrap();
        assert_eq!(leaves.len(), 3);
        assert_eq!(
            leaves
                .iter()
                .filter(|leaf| **leaf == Fr::from(0u64))
                .count(),
            2
        );
        let legacy_leaf = circuit_identity_zk::hash_to_field(&Sha256::digest(
            b"arx-id-legacy/v1pre-v1-opaque-hash",
        ));
        assert!(leaves.contains(&legacy_leaf));
        assert_eq!(
            root,
            circuit_identity_zk::AttestedTree::from_leaves(
                &circuit_identity_zk::poseidon_params(),
                &leaves,
            )
            .unwrap()
            .root()
        );
    }
}
