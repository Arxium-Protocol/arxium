# Programmable accounts — state schema 26

## Milestone coverage and release status

- **M1:** immutable threshold issuer/admin roles run through the real executor.
  `account_policy::tests::threshold_issuer_and_all_admin_roles_execute_in_the_real_executor`
  registers and issues an asset, registers an attestor, performs an authorized
  forced transfer, and freezes another issuer's asset. Threshold signatures are
  verified before role dispatch. The SDK/CLI, Console, API assembler and mobile
  codecs provide building, individual signing and assembly.
- **M2:** `AccountEntry.programmable` commits the current policy, spending
  counters and pending recovery to the account's Merkleized row. Owners rotate
  without changing the address, balances, nonce, identity or issuer/admin roles.
  State schema is **26**; SDK tooling is **0.1.5**.
- **M3:** the account circuit enforces bounded per-asset spending windows and
  recipient allowlists over the runtime's proposed state updates. Same-block
  overlay execution and proof-only block replay use the current policy.
- **Post-mainnet:** session and guardian-recovery code is implemented, but
  `ChainParams.account_extensions_enabled` defaults to **false**. Activate only
  through a voted `GovernanceAction::SetChainParams` after the corresponding
  external audit and release decision.
- **Release work still required:** coordinated devnet reset and an independent
  external circuit audit. Local tests do not constitute that audit. No live
  deployment or operator data reset is performed by this implementation.

## Fixed policy menu

`AccountPolicy` contains:

| Field | Rule |
| --- | --- |
| `owners` | 1–16 unique, strictly ascending, non-weak Ed25519 keys; threshold 1–N |
| `limits` | At most 16 assets, one limit per asset; positive `period_blocks`; amounts are base units |
| `recipients` | `None` is unrestricted; `Some([])` permits no recipients; at most 64 sorted, unique addresses |
| `sessions` | At most 16 unique keys; one asset, explicit recipient list, exclusive expiry and remaining principal allowance |
| `recovery` | Guardian threshold plus a positive block delay |

There are no arbitrary programs. The appended CoreChain payload family is
`ActionPayload::AccountPolicy` (variant **43**). Its nested discriminants are:

0. `SetPolicy { policy }`
1. `RotateMembers { owners }`
2. `AddSession { session }`
3. `RevokeSession { public_key }`
4. `StartRecovery { owners }`
5. `CancelRecovery`
6. `ExecuteRecovery`

Initial enrollment is authorized by the account's existing personal key or
immutable multisig. Once enrolled, legacy address-key signatures are rejected;
the stored owner threshold is authoritative. `RotateMembers` also clears
sessions and any pending recovery. `SetPolicy` is an owner-approved replacement:
unchanged limits retain their counters; changed/removed limits do not. It clears
pending recovery. Policies cannot be removed back to legacy authorization.

## Spending and clock semantics

The window is `execution_block_height / period_blocks`, anchored at genesis.
The height is supplied by the block executor, which accepts blocks extending the
tip by exactly one. The proof adjudicator uses the attested header's height.
Neither a member signature nor the payload supplies a spending clock. A change
to block interval changes elapsed wall time, not the definition of a window.

Counters accumulate actual **net debits** of the sender's native/asset balance
rows after business execution and metered fees. This covers native transfers,
staking, token creation fees, asset/token transfers, burns and corporate payouts
where the sender's balance is debited. Self-transfers are balance-neutral except
for fees. Incoming credits do not reduce an already accumulated counter. Minting
to another holder is subject to the recipient allowlist, but is not a debit of
the issuer's existing balance and does not count as spending that balance.
Supply/issuance and regulatory forced-transfer authorization keep their separate
business rules; this policy governs the **action sender**, not the forced-from
party's permission to be moved by an authorized issuer/admin.

Native fees for ordinary actions count toward native limits even if the action also credits the sender;
the native debit counter has the metered fee as its floor. All external balance credits produced by
the action must satisfy the sender's allowlist; staking subaccounts and a token
creation treasury payment are included. A transfer's explicit recipient is
checked even for a self/zero-value transfer. Rejected actions do not consume
nonces, fees, allowances or counters because their proposed updates are discarded.
State reversion also reverts the account policy and its counters.

Stateful witnesses add a fixed 5,000 weight allowance for checking the bounded
stored menu, in addition to payload/encoded-byte costs. This prevents large
stored policies from being validated at the price of a plain-key transfer.
The existing metering table is hand-set; include worst-case menu calibration in
the external audit/release review.

Session keys can only submit native, regulated-asset or token **transfer** actions.
They cannot mint, burn, stake, change policy or exercise issuer/admin roles. Both
the account-wide limits/allowlist and the session's asset/recipients/remaining
allowance apply. Sessions require a native spending limit to bound transaction
fee exposure, including zero-value and asset-only transfers. Sessions expire at
`height >= expires_at`. Replacing a session requires owner revocation/re-addition.

## Cancellable recovery

Guardians can only propose and finalize recovery. `StartRecovery` commits new
owners and `execute_after = height + delay_blocks` with checked arithmetic.
An existing proposal cannot be replaced to reset its delay. `ExecuteRecovery`
needs a fresh current-guardian threshold action at or after that height; it
changes owners and clears all sessions. Execution is explicit, not automatic.

Current owners can cancel during or after the delay, until execution has landed.
All fixed-menu policy-management actions consume a nonce and ordinary fee but are
exempt from the spending budget: an exhausted/zero limit must not prevent owner
rotation, session revocation or cancellation. Unchanged spending limits retain
their counters even when re-submitted. Guardian recovery actions likewise pay
fees without consuming the owner's counters. These management actions cannot
carry a spend. As with other actions, same-block ordering determines which
accepted action wins a race at the execution height.

## Witness format

The action wire envelope remains `{sender, nonce, signature, payload}`. Everyone
signs the same canonical bytes: sender + nonce + encoded payload. Stateful
witnesses are hex:

- owner: `a7 00 || canonical_multisig_witness`
- session: `a7 01 || public_key(32) || signature(64)`
- guardian: `a7 02 || canonical_multisig_witness`

The threshold witness is the existing `threshold || member_count || members ||
threshold × (member_index || signature)`, with strictly ascending signer indices
and exactly the threshold number of signatures. The prefixed policy must match
current state, not the address's original hash. Admission, execution and
proof-backed replay all perform state-aware cryptographic verification. The
runtime then checks the capability's payload scope and execution height.

For historical cryptographic verification, provide the **proven pre-action**
policy, including same-block earlier rotations. Today's account policy is not a
substitute. SDK `verifySignedAction(action, preStatePolicy)` verifies the witness;
execution replay proves the limits and capability scope.

## Tooling

### SDK / CLI

Build an input file with `threshold`, sorted hex `members`, `nonce`, and `payload`
as `{name, input}`. For enrollment use `setAccountPolicy` with `{policy: ...}`.
SDK policy fields use camel case; integers wider than a byte are decimal strings
inside policy configuration (e.g. `periodBlocks`, `expiresAt`, `delayBlocks`).
Use `"native"` or `{ "asset": "arxasset1..." }` as the asset selector.

After enrollment set `sender` to the stable account ID and `mode: "owner"` (or
`"guardian"` for recovery). The CLI verifies that mode against the current node
policy before signing or assembly. Do not change sender to the member's address.

```sh
arx multisig build proposal.json > request.json
arx --key member-a.json multisig sign request.json > signed-a.json
arx --key member-b.json multisig sign signed-a.json > signed-ab.json
arx multisig combine signed-ab.json > action.json
arx submit action.json
arx multisig link signed-ab.json https://YOUR-CONSOLE/console/issuer/multisig
arx verify SIGNATURE --policy proven-pre-action-policy.json
```

The SDK exports `encodeAccountPolicy`, `signPolicyMember`,
`assemblePolicySignature`, `assembleSessionSignature` and `verifyPolicySignature`.
`sdk/ts/fixtures/account-policies.json` is generated by Rust and pins all seven
policy payloads, signing bytes and threshold witness encodings.

### Console

The Multisig signer page includes a fixed action selector and policy configuration
editor. Enrollment uses existing keys. Later co-sign requests verify members and
threshold against the node's current owner/guardian policy. Normal issuer actions
also select the current policy, so local saved original members do not override
rotation. Console retains its 10-member and 4 KiB submission-payload limits.

### API / mobile

`POST /multisig/assemble` accepts `{sender, nonce, threshold, members, payload,
signatures, mode}`. `members` are public-key hex strings; `signatures` are objects
with `public_key` and `signature`. `payload` is a JSON array of bytes. `sender`
may be omitted for legacy derivation. Modes are `legacy`, `owner`, `guardian`.
Owner/guardian assembly reads the current account policy before verifying each
contribution. It returns a node-ready action; submit it through `POST /actions`.
No private keys are submitted to the API. The assembler does not replace node
execution/prechecks, and policy/nonce changes can invalidate an assembled action.

Swift `ArxProgrammableAccount` and Kotlin `ProgrammableAccount` encode the fixed
menu, derive threshold IDs, sign the stable account envelope, verify contributions
and assemble canonical witnesses. Recipient entry/QR validation accepts tagged
multisig accounts while login-key decoding remains strictly personal-key-only.

## Devnet reset and audit handoff

Schema 25 stores cannot open under schema 26. This is a positional bincode/state
root change; `serde(default)` only preserves old JSON genesis specifications.
Coordinate a fresh genesis/reset across validators, reset dependent indexer state,
and redeploy matching clients/SDK. Archive the old devnet data before applying
the existing operator reset procedure. Do not patch the schema marker in place or
reuse an old checkpoint/snapshot as the new genesis. Keep extensions disabled in
launch specs. Record the new genesis hash and verify node/client agreement.

The external audit should cover `core/primitives/src/{policy,action,state}.rs`,
`circuits/account/src/policy.rs`, runtime dispatch/fee/effect enforcement, mempool
admission, executor overlays, and proof-only adjudication. Include malformed and
weak keys, witness malleability, role separation, rotation/replay, all balance
debit paths, window boundaries/reorgs, session fee exposure and recovery races.
Complete independent findings remediation and re-audit before mainnet; session/
recovery activation needs the same review before its post-mainnet vote.
