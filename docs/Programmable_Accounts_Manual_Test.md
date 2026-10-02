# Programmable accounts: local manual test

## Running services

| Service | URL |
|---|---|
| Console | http://localhost:3000 |
| Console sign-in inbox | http://localhost:8025 |
| API | http://localhost:8080/readyz |
| Test chain: sessions/recovery enabled | http://localhost:30333/status |
| Launch-gate chain: extensions disabled | http://localhost:30343/status |

Both chains use disposable local keys and 1-second blocks. The local test fee
parameters are `action_fee = 1,000,000` and `weight_fee = 1,000` IUM. The prepared
UI multisig has 1,000 ARX; its three individual member wallets have 100 ARX each.
The automated account is separate. The completed run passed **41 live checks**;
its results are in `$DEMO_HOME/test-report.json`. A fresh chain was subsequently
started after clearing build artifacts, so the manual-test account is untouched.

## 1. Terminal setup

Run these commands in one terminal on this Mac:

```sh
cd /Users/yassinemzoughi/Desktop/Arxium_Project/arxium
export DEMO_HOME=/var/folders/2x/m18r4sn957z2zcbc1ggr12s00000gn/T/opencode/programmable-accounts-demo
export ARX_RPC=http://127.0.0.1:30333
export ARX_PASSPHRASE=local-demo-only

node scripts/programmable-accounts-demo.mjs status
```

Check that both `tip_height` values advance. The UI account is:

```text
arx1q9f87yz237vfru7pdq55qjzgy6rz796l7p85rzkmvv6rs8alyaejv7e9ngs
```

Use this sequence once on the fresh UI account. Do not enroll through both the
CLI and Console: choose one enrollment method below, then continue at step 3.

## 2. M1: individual signing and threshold assembly; enroll policy

```sh
node sdk/ts/dist/cli.js multisig build "$DEMO_HOME/ui-enroll-proposal.json" > "$DEMO_HOME/ui-request.json"

node sdk/ts/dist/cli.js --key "$DEMO_HOME/keys/ui-a.json" multisig sign "$DEMO_HOME/ui-request.json" > "$DEMO_HOME/ui-signed-a.json"

# Expected failure: one member cannot assemble a 2-of-3 action.
node sdk/ts/dist/cli.js multisig combine "$DEMO_HOME/ui-signed-a.json"

node sdk/ts/dist/cli.js --key "$DEMO_HOME/keys/ui-b.json" multisig sign "$DEMO_HOME/ui-signed-a.json" > "$DEMO_HOME/ui-signed-ab.json"
node sdk/ts/dist/cli.js multisig combine "$DEMO_HOME/ui-signed-ab.json" > "$DEMO_HOME/ui-enroll-action.json"
node sdk/ts/dist/cli.js submit "$DEMO_HOME/ui-enroll-action.json"

# After the next block, policy should be non-null.
node scripts/programmable-accounts-demo.mjs ui-policy
```

**Expected:** the one-signature command fails with `need exactly threshold
signatures`; the two-signature action is accepted. The account policy shows two
required signatures, three owners, a 150,000,000-IUM native budget, the allowed
recipient, and a 10-block guardian recovery delay. This recovery setting is for
the extensions-enabled local test chain, not the launch configuration.

## 3. M3: spending limit and recipient allowlist

```sh
node scripts/programmable-accounts-demo.mjs ui-transfer allowed 60000000
node scripts/programmable-accounts-demo.mjs ui-transfer allowed 60000000
node scripts/programmable-accounts-demo.mjs ui-transfer allowed 60000000 --reject
node scripts/programmable-accounts-demo.mjs ui-transfer outsider 1 --reject
node scripts/programmable-accounts-demo.mjs ui-policy
```

**Expected:** the first two transfers confirm. The third is dropped with `period
spending limit exceeded`. The outsider transfer is dropped with `recipient is not
allowed by account policy`. Fees count toward the native limit; failed actions
must not change the balance or nonce. The helper checks those invariants.

The allowed recipient is:

```text
arx1p0h0t20x08n28cf5lcncx7llxtrukh6agn4qn09su4pt444ycrxqh8gefy
```

The outsider is:

```text
arx1mxljzjr532zu38d94tvwuzc0ctgstlfe6sdyc7t9xc657zhzjqxqlqw7ug
```

The 41-check run additionally tested asset limits and an 8-block native window:
a rejected transfer succeeded after rollover, with the counter reset to the new
window. The same signed retry then correctly reported `confirmed`.

## 4. M2: rotate owners, retaining the account

```sh
node scripts/programmable-accounts-demo.mjs ui-rotate
node scripts/programmable-accounts-demo.mjs ui-transfer allowed 1 --old-key --reject
node scripts/programmable-accounts-demo.mjs ui-transfer allowed 1
node scripts/programmable-accounts-demo.mjs ui-policy
```

**Expected:** rotation confirms; the account address is unchanged; its owner keys
are now `next-a`, `next-b`, `next-c`. Original-owner signatures fail with a policy
mismatch. The new owners can transfer. Rotation is allowed even when a spending
budget is exhausted, but does not reset unchanged spending counters.

## 5. Session keys: allowance, expiry and revocation

First increase the native budget for the remaining tests:

```sh
node scripts/programmable-accounts-demo.mjs ui-reset-budget
node scripts/programmable-accounts-demo.mjs ui-add-session 120 1000000
node scripts/programmable-accounts-demo.mjs ui-session-transfer allowed 1000000
node scripts/programmable-accounts-demo.mjs ui-session-transfer allowed 1000000 --reject
node scripts/programmable-accounts-demo.mjs ui-revoke-session
node scripts/programmable-accounts-demo.mjs ui-session-transfer allowed 0 --reject
```

**Expected:** the first session transfer confirms; the second exceeds its
allowance. After revocation, even a zero-value session transfer fails signature
verification.

For expiry, re-add the revoked key with a short lifetime and an unused allowance:

```sh
node scripts/programmable-accounts-demo.mjs ui-add-session 6 1000000
sleep 8
node scripts/programmable-accounts-demo.mjs ui-session-transfer allowed 0 --reject
```

**Expected:** expiry rejects the action. The live suite also verified that session
keys cannot rotate owners or exercise policy-management authority.

## 6. Recovery: early rejection, cancellation and delayed execution

```sh
node scripts/programmable-accounts-demo.mjs ui-start-recovery
node scripts/programmable-accounts-demo.mjs ui-execute-recovery --reject
node scripts/programmable-accounts-demo.mjs ui-cancel-recovery
node scripts/programmable-accounts-demo.mjs ui-execute-recovery --reject

node scripts/programmable-accounts-demo.mjs ui-start-recovery
node scripts/programmable-accounts-demo.mjs ui-wait-recovery
node scripts/programmable-accounts-demo.mjs ui-execute-recovery
node scripts/programmable-accounts-demo.mjs ui-policy
```

**Expected:** early execution fails with `recovery timelock has not elapsed`;
cancellation clears the pending recovery; executing a cancelled recovery fails
with `no pending recovery`. The second proposal executes after its stored height.
Owners return to `ui-a/ui-b/ui-c`; the address remains unchanged; sessions are
cleared and `pending_recovery` is null.

## 7. Launch gate

```sh
node scripts/programmable-accounts-demo.mjs ui-launch-gate
```

**Expected:** the separate chain on 30343 rejects the extension-bearing policy
with `session keys and recovery are not activated`.

## Console walkthrough

1. Open http://localhost:3000 and choose email sign-in. Use a local test address,
   e.g. `manual-a@arxium.test`.
2. Open http://localhost:8025, refresh, and copy the six-digit code. Complete
   onboarding with test profile details.
3. To load the prepared encrypted test key, run this command, copy its JavaScript
   output, and execute it in the browser's developer console **on localhost:3000**:

   ```sh
   node scripts/programmable-accounts-demo.mjs browser-key ui-a
   ```

   This uses the normal authenticated key API. Use a fresh local account without
   an existing Console signing key. Then unlock it in Settings with
   `local-demo-only`.
4. Open http://localhost:3000/console/issuer/multisig. Enter these three addresses,
   choose **2 of 3**, and click **Save & act as this multisig**:

   ```text
   arx1af9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkqq44q6e
   arx1zwv0vtrdrfzhc5d6df9470da9a5le2fjzcscmjye0eqkh5taj09qr6dcas
   arx1l5tjgwz65rr4ke8m0rxkqtapmxglm6lhdvfutrkhqt4vsd0f7cvqwz2wdg
   ```

5. In **Programmable account**, select **Set policy and spending controls** and
   paste `$DEMO_HOME/ui-policy-input.json` into the JSON editor. If already
   enrolled, the editor instead loads the current configuration.
6. Click **Propose account action**. The co-sign page should show the decoded
   policy and **1 of 2 signatures**. One member cannot submit it.
7. In a separate browser profile, sign into another local account, install
   `ui-b` using `browser-key ui-b`, unlock it, and open the copied co-sign link.
   Click **Sign with my key**, then **Submit to chain**. Verify confirmation and
   inspect `ui-policy` in the terminal.

If you enroll through this Console flow, skip the CLI enrollment in step 2.
The loaded test keys, database, OTP inbox and chain data are local-only.

## Logs and stopping the demo

Logs, encrypted test keys, chain specs, process IDs and test results are in
`$DEMO_HOME`. Stop only the recorded demo processes:

```sh
node -e 'const fs=require("node:fs");for(const pid of Object.values(JSON.parse(fs.readFileSync(process.env.DEMO_HOME+"/pids.json","utf8")))){try{process.kill(pid,"SIGTERM")}catch{}}'
pg_ctl -D "$DEMO_HOME/postgres" stop
```

Redis now runs natively on port 6380 and is included in `pids.json`; Docker is not
needed for the working API. The local demo is verification tooling. The coordinated deployed-devnet reset
and independent external circuit audit remain release tasks.
