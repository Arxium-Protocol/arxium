# Compliance rules — rule → circuit → error

What the chain enforces on regulated assets, where each rule lives, and the
exact error a rejected action carries. Written for a supervisor reading the
rules and for anyone decoding an error in Verify or the Console: the
**Error** column is the string that surfaces verbatim as
`GET /actions/{signature}` → `{"status":"dropped","reason":"…"}` and in the
block's `dropped` list (`GET /blocks/{h}/effects`). There are no numeric codes; the message is the code.

Source of truth is the code this document cites. If they disagree, the code
is right and this file is stale — fix the file.

## 1. Model

- **Native balance vs. asset balance.** Fees, staking and plain transfers use
  the native balance and require no KYC. Only balances of a registered
  *asset* (`arxasset1…`) are compliance-gated. `circuits/rwa-asset`.
- **Attestation.** An account is *attested* when a registered attestor has
  set its `identity_hash`, and that attestor is still registered. An
  attestation from a since-deregistered attestor is void immediately, with
  no per-account action. `circuit_identity::is_attested`.
- **Claims.** An attestation carries claim topics — `Kyc`, `Aml`,
  `Accredited`, `Jurisdiction` — and optionally an ISO-3166-1 alpha-2
  jurisdiction. Re-granting replaces both outright (a narrower re-grant takes
  a claim away). `circuit_identity::apply_grant_attestation`.
- **Asset rules** are set by the issuer per asset: `compliance_required`,
  `required_claims`, `allowed_jurisdictions`, `max_attestation_age`,
  `max_holders`, `max_balance_per_holder`, `max_supply`, plus the
  `frozen` / `issuance_locked` switches.
- **Roles.** Three chain-wide admin addresses seeded at genesis — attestor
  admin, freeze admin, recovery admin — one address per role. Per asset: the
  issuer. Any of these may be a multisig address (up to 16 ed25519 members,
  threshold 1..=N; `xc_primitives::multisig_address`, SDK `multisigAddress`),
  in which case every action from it must carry exactly `threshold` member
  signatures — checked on chain in `Action::verify_signature`.
  Attestors are a registry, many at once. `arxd/runtime/src/identity.rs`
  (`require_admin`), `asset.rs` (`require_issuer`).
- **Reasons.** Every admin-gated action (forced transfers, freeze/unfreeze,
  attestor register/deregister) carries a free-text `reason`, non-blank and
  ≤ 512 bytes. It is not written to state; the block carrying the action is
  the audit record. `asset::check_reason`.

## 2. Who may do what

| Action | Allowed sender | Enforced in |
|---|---|---|
| `RegisterAttestor` / `DeregisterAttestor` | attestor admin | `runtime::identity::require_admin(Attestor)` |
| `GrantAttestation` / `RevokeAttestation` | any *registered* attestor | `circuit_identity::require_attestor` |
| `VerifyCredential` (ZK) | the account itself | `circuit_identity::apply_verify_credential` |
| `RegisterAsset` | anyone (becomes issuer) | `runtime::asset::register_asset` |
| `IssueAsset`, `IssueAssetTo`, `BurnAsset`, `LockIssuance`, `TransferIssuer`, `SetAssetMetadataUri`, `SetAssetLimits` | issuer | `runtime::asset::require_issuer` |
| `SetHolderFrozen`, `LockHolderAmount(Until)`, `IssuerForcedTransfer`, `RecoverHolder` | issuer | `require_issuer` |
| `SetAssetFrozen` | issuer **or** freeze admin | `runtime::asset::set_frozen` |
| `ForcedTransfer` | recovery admin | `runtime::asset::forced_transfer` |
| `TransferAsset` | any holder — subject to §3 | `circuit_rwa_asset::apply_compliant_transfer` |
| `JoinValidator` | attested account, if `ChainParams.validator_attestation_required` | `runtime::staking` |

Authorization errors (all `arxd/runtime`):

| Error | Meaning |
|---|---|
| `{sender} is not the {role}` | sender is not the seeded admin for that role |
| `chain has no {role} configured` | genesis seeded no address for the role; the action can never succeed on this chain |
| `only the issuer ({issuer}) of {asset} may do this, got {sender}` | issuer-only action from someone else |
| `{sender} is neither the issuer of {asset} nor the freeze admin` | `SetAssetFrozen` |
| `only the recovery admin may force a transfer` | `ForcedTransfer` |
| `{addr} is not a registered attestor` | grant/revoke from an unregistered address, or deregistering one |
| `{addr} is already a registered attestor` | deregister first to change its name |
| `{what} needs a non-empty reason` / `reason is N bytes, over the 512-byte limit` | missing/oversized audit reason |
| `unknown asset {asset}` | no such `arxasset1…`; never an implicit create |
| `{validator} has no attestation from a registered attestor, and this chain requires one to validate` | `JoinValidator` on an attestation-required chain |

## 3. Transfer gates (`TransferAsset`)

Checked in this order by `circuit_rwa_asset::apply_compliant_transfer`; the
first failure is the error. **Both** sender and recipient must pass the party
checks — a transfer is compliant only if both ends are. The issuer's own
balance is exempt from the two prospectus limits (it is the treasury, not an
investor).

| # | Rule | Applies to | Error |
|---|---|---|---|
| 1 | Asset not frozen | asset | `{asset} is frozen: no transfers until it is unfrozen` |
| 2 | Party not issuer-frozen | sender, then recipient | `{address} is frozen for {asset} and may neither send nor receive it` |
| 3 | Party attested (if `required_claims` non-empty **or** `compliance_required`) | sender, recipient | `compliance check failed: {address} is not KYC'd/allowlisted` |
| 4 | Party holds every topic in `required_claims` | sender, recipient | `{address} is missing the {Topic} claim required by {asset}` |
| 5 | Attestation younger than `max_attestation_age` blocks (an attestation with no recorded height counts as expired) | sender, recipient | `{address}'s attestation is {age} blocks old, over {asset}'s limit of {max_age}` |
| 6 | Party's jurisdiction is in `allowed_jurisdictions` (unknown jurisdiction = rejected, not waved through) | sender, recipient | `{address}'s jurisdiction ({Some("XX")|None}) is not among those {asset} permits` |
| 7 | Recipient would not be a *new* holder past `max_holders` | recipient (non-issuer) | `{asset} already has {n} holders, the cap: {address} cannot become one` |
| 8 | Recipient's resulting balance ≤ `max_balance_per_holder` | recipient (non-issuer) | `{address} would hold {resulting} of {asset}, over the per-holder limit of {limit}` |
| 9 | Nonce matches | sender | `invalid nonce for {sender}: expected {e}, got {g}` |
| 10 | Amount within *unlocked* balance | sender | `{sender} has {locked} of {asset} locked: only {available} of {balance} is spendable, needs {amount}` |
| 11 | Amount within balance | sender | `insufficient {asset} balance for {sender}: has {b}, needs {a}` |

Notes:
- Rules 3–4 vs. `compliance_required`: when `required_claims` is non-empty
  it is authoritative and the bool is ignored; the bool is the fallback for
  assets registered before claim topics existed. Never both.
- Rule 5 clock: `attested_at` is the block height of the last grant. A
  re-grant resets it.
- Locks (rule 10) can carry an expiry height; an expired lock is dropped
  before the arithmetic, so it never blocks a transfer after `expires_at`.

### Wallet-side pre-check

`GET /accounts/{addr}/assets` reports `eligibility_reason` per asset for the
*sender* side only (recipient and nonce can't be known in advance). Same
gate order as above:

| `eligibility_reason` | Gate |
|---|---|
| `eligible` | — |
| `asset_frozen` | 1 |
| `holder_frozen` | 2 |
| `missing_attestation` | 3 |
| `missing_required_claim` | 4 |
| `attestation_expired` | 5 |
| `jurisdiction_not_allowed` | 6 |
| `no_transferable_balance` | 10 (balance − locked = 0) |

These strings are an RPC contract: new reasons are added, existing ones are
never renamed. `circuit_rwa_asset::TransferEligibility::reason`.

## 4. Issuance and supply

| Action | Rule | Error |
|---|---|---|
| `IssueAsset` (mint to issuer) | issuance not locked | `issuance of {asset} is locked` |
| | `total_supply + amount ≤ max_supply` | `issuing {amount} of {asset} would raise supply to {r}, over the cap of {cap}` |
| | no u128 overflow (its own error, never a silent clamp) | `supply of {asset} would overflow u128` |
| | amount > 0 | `issue amount must be positive` |
| `IssueAssetTo` (mint straight to an investor) | as above, **plus** recipient passes gates 2–8 — the issuer itself is *not* checked (it never holds the units) | gate errors from §3 |
| `BurnAsset` (issuer's own units only) | amount ≤ issuer balance | `burning {amount} of {asset} exceeds the issuer's balance of {b}` |
| | amount ≤ total supply (state-corruption guard) | `burning {amount} of {asset} exceeds its total supply of {s}` |
| | amount > 0 | `burn amount must be positive` |
| `LockIssuance` | one-way: sets `issuance_locked` and pins `max_supply = total_supply` | — |
| `SetAssetLimits` | `max_balance_per_holder ≠ 0`; a `max_holders` below the current count is accepted (blocks new holders, evicts none) | `max_balance_per_holder of 0 would make the asset unholdable` |

Pulling supply back from a holder is deliberately two steps —
`IssuerForcedTransfer` to the issuer, then `BurnAsset` — so the chain shows
both.

## 5. Holder controls (issuer)

| Action | Effect | Error |
|---|---|---|
| `SetHolderFrozen` | holder out of (or back into) circulation for this asset, both directions, whatever its claims say | — (a raw write; does not touch an expired lock) |
| `LockHolderAmount` | locks `amount` of the holder's balance; `Until` variant self-releases at that height. One expiry per holder: a new lock replaces it, so the latest lock's term governs the whole locked amount | `cannot lock {amount} of {asset} for {holder}: balance is {b}, already locked {l}` |
| | unlock ≤ locked | `cannot unlock {amount} of {asset} for {holder}: only {locked} is locked` |
| | amount > 0; expiry after current height | `lock amount must be positive` / `lock expiry {until} is not after the current height {h}` |
| `RecoverHolder` | moves everything `lost` holds — balance, locked amount **and** freeze flag — to `replacement`, which must pass gates 2–8 (a lost wallet is not a way around KYC); freeze is OR-ed so recovery can't launder a frozen holder | gate errors from §3; `recovery needs a different replacement address` |

## 6. Overrides — what compliance does *not* gate

| Action | Sender | Gates skipped | Kept |
|---|---|---|---|
| `ForcedTransfer` | recovery admin | attestation, claims, jurisdiction, age, holder limits, asset freeze, holder freeze | `from` must hold the balance (`insufficient {asset} balance for {from}…`); cannot mint; reason required |
| `IssuerForcedTransfer` | issuer | same | same |

This is by design: court orders, sanctions and lost keys are exactly the
cases ordinary compliance refuses, and freezing an instrument is exactly when
a regulator most needs to move it. The `reason` on the action and the block
it lands in are the audit trail.

## 7. Registration validity (`RegisterAsset`, `GrantAttestation`)

| Rule | Error |
|---|---|
| `asset_id` non-empty, `[a-z0-9_-]`, length-capped; unique per issuer (`arxasset1…` is derived from issuer + id) | `asset_id must not be empty`, charset/length messages, `{issuer} already has an asset with id {id} ({ref})` |
| `symbol` `[A-Z0-9]`, `name` non-empty, `decimals` renderable, `metadata_uri` length-capped | `symbol {s} contains {c}: only A-Z and 0-9 are allowed`, … |
| jurisdiction codes (grant **and** asset allowlist) are 2-letter uppercase ISO-3166-1 alpha-2 — one validator on both sides so they can never disagree | `jurisdiction {code} is not a 2-letter uppercase ISO-3166-1 alpha-2 code` |
| `RevokeAttestation` needs an existing account | `account {addr} not found` |
| `VerifyCredential` (ZK) | `account has no identity_hash to prove`, `identity_hash is not a valid field element`, `malformed zk proof bytes`, `sender address is not a valid public key`, `zk credential proof failed verification` |

## 8. Where an error shows up

1. **Admission** (`POST /actions`): only signature, nonce window and size —
   compliance is *not* checked here, so a non-compliant action is accepted
   into the mempool.
2. **Execution**: the producer runs the gates when it drains the action into
   a block. A failure drops the action; it never lands in a block.
3. **Reading it back**: `GET /actions/{signature}` →
   `{"status":"dropped","reason":"<string from the tables above>"}` while
   this node still remembers it (in-memory, bounded; a restart forgets).
   The block that drained it lists the same `reason` (with the sender)
   under `dropped` in `GET /blocks/{h}/effects` — persistent, and what
   Verify and the Console render.
4. The dropped action consumed no nonce, so the client resubmits with the
   same nonce after fixing the cause.

## 9. Things a supervisor should know are *not* rules

- No transfer-amount thresholds, velocity limits, or travel-rule fields.
- No per-transfer attestor approval: the attestor vouches once (with
  topics), the chain checks state at execution.
- No automatic expiry sweep: an expired attestation is only noticed when it
  is used (gate 5). `is_attested` alone has no age limit — the validator
  admission gate uses it un-aged.
- Native-balance transfers and fees are never gated.
