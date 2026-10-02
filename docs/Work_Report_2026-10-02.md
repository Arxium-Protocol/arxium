# One-page work report — 2 October 2026

**Project:** Arxium programmable accounts

**Status:** Implementation completed; local end-to-end verification passed.

## Work completed today

- **M1 — threshold roles:** proved 2-of-3 issuer and attestor/freeze/recovery-admin
  actions through chain execution. Added building, individual signing and witness
  assembly in SDK/CLI, Console, API and Swift/Kotlin tooling.
- **M2 — stateful policies:** added policies, spending counters and pending
  recovery to account state. Owner rotation retains the account address, balance
  and issuer/admin ownership. State schema is **26**; SDK is **0.1.5**.
- **M3 — spending controls:** implemented per-asset, block-height spending windows
  and recipient allowlists, including enforcement during proof-backed replay.
- **Post-mainnet capabilities:** implemented transfer-only session keys and
  guardian recovery with an owner-cancellable timelock. Extensions remain
  disabled by default; the dedicated local test chain enables them for testing.
- **Retry-status fix:** live testing exposed stale rejection records masking a
  later successful retry. Re-admission now clears the old rejection, and
  committed history takes precedence. Added regression tests.

## Verified working

**41 live checks passed** against real local chain/API services: threshold
rejection and successful issuance; all three admin roles; stable-address
rotation and rejection of old owners; native/asset spending limits; recipient
restrictions; window rollover and successful retry; session allowance, expiry,
revocation and authority restrictions; early recovery rejection, cancellation,
delayed execution, session clearing and rejection of former owners; launch-gate
rejection of disabled extensions. Rejected actions retained their nonce/balance.

Other passed checks include Rust runtime/primitives/executor/storage tests,
workspace compilation and strict Clippy; SDK codec/CLI tests; Console
type-check/tests/lint; API tests; Android tests; Swift/Rust signing vectors.
The retry fix passed **10 mempool tests and 34 RPC tests**.
Browser smoke checks also passed: local email sign-in, encrypted test-key loading,
wallet unlock, multisig selection and the enabled policy form at desktop/mobile
sizes. The browser check did not submit the manual account's enrollment.

## Local test environment and handoff

Console: **localhost:3000** · API: **localhost:8080** · OTP inbox:
**localhost:8025** · extensions test chain: **localhost:30333** · launch-gate
chain: **localhost:30343**. Prepared test keys, funded accounts, logs and the
41-check result file are available in the local demo directory. Manual steps:
[`Programmable_Accounts_Manual_Test.md`](Programmable_Accounts_Manual_Test.md).

## Remaining release work

Coordinate the deployed devnet reset and matching-client rollout; commission
and remediate an independent external circuit audit before mainnet. Local test
activation is not production activation. A full iOS app build was not performed;
Swift codec/signature interoperability was verified separately.
