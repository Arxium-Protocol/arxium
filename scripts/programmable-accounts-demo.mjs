#!/usr/bin/env node
// Local test keys only. Requires `npm run build` in sdk/ts and a built arxd.
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve, join } from "node:path";
import {
  Writer, encodeAddress, encodePayload, fromHex, toHex, importSeed, signAction,
  multisigAddress, multisigSignature, assembleSessionSignature, submitBody,
  deriveAssetRef, toKeyFile, wrapPkcs8,
} from "../sdk/ts/dist/index.js";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const home = process.env.DEMO_HOME ?? "/var/folders/2x/m18r4sn957z2zcbc1ggr12s00000gn/T/opencode/programmable-accounts-demo";
const rpc = process.env.DEMO_RPC ?? "http://127.0.0.1:30333";
const launchRpc = "http://127.0.0.1:30343";
const api = process.env.DEMO_API ?? "http://127.0.0.1:8080";
const password = "local-demo-only";
const aliases = ["original-a", "original-b", "original-c", "next-a", "next-b", "next-c", "ui-a", "ui-b", "ui-c", "guardian-a", "guardian-b", "guardian-c", "session", "allowed", "outsider", "expiring-session", "revocable-session"];
const groups = { original: aliases.slice(0, 3), next: aliases.slice(3, 6), ui: aliases.slice(6, 9), guardians: aliases.slice(9, 12) };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const jsonFile = async (name, value) => writeFile(join(home, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
const readProfile = async () => JSON.parse(await readFile(join(home, "profile.json"), "utf8"));
const publicKey = seed => Buffer.from(createPublicKey(createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${seed}`, "hex"), format: "der", type: "pkcs8" })).export({ format: "jwk" }).x, "base64url");
const threshold = (profile, group) => ({ threshold: 2, members: groups[group].map(alias => profile.keys[alias].publicKey).sort() });
const policyFor = (profile, group = "original") => ({ owners: threshold(profile, group),
  limits: [{ asset: "native", periodBlocks: "100000", amount: "150000000" }],
  recipients: [profile.keys.allowed.address], sessions: [],
  recovery: { guardians: threshold(profile, "guardians"), delayBlocks: "10" } });
function fromNodePolicy(p) {
  const owners = p => ({ threshold: p.threshold, members: p.members.map(m => toHex(Uint8Array.from(m))) });
  const asset = a => a === "Native" ? "native" : { asset: a.Asset };
  return { owners: owners(p.owners), limits: p.limits.map(l => ({ asset: asset(l.asset), amount: String(l.amount), periodBlocks: String(l.period_blocks) })),
    recipients: p.recipients, sessions: p.sessions.map(s => ({ publicKey: toHex(Uint8Array.from(s.public_key)), expiresAt: String(s.expires_at), asset: asset(s.asset), allowance: String(s.allowance), recipients: s.recipients })),
    recovery: p.recovery ? { guardians: owners(p.recovery.guardians), delayBlocks: String(p.recovery.delay_blocks) } : null };
}
async function get(path, base = rpc) {
  const response = await fetch(`${base}${path}`);
  if (!response.ok) throw new Error(`${base}${path}: ${response.status} ${await response.text()}`);
  const value = await response.json();
  return path === "/status" ? { ...value, height: value.tip_height } : value;
}
async function waitHeight(height, base = rpc) {
  for (let i = 0; i < 180; i++) {
    const status = await get("/status", base);
    if (status.height >= height) return status;
    await pause(500);
  }
  throw new Error(`height ${height} did not arrive`);
}
function encode(name, input) {
  // The attestor-admin variant is not in the SDK's user-facing codec menu.
  if (name === "registerAttestor") return new Writer().varint(15).string(input.attestor).string(input.name).string(input.reason).bytes();
  return encodePayload({ name, input });
}
async function build(profile, sender, name, input, options = {}) {
  const base = options.rpc ?? rpc;
  const account = await get(`/accounts/${sender}`, base);
  const payload = encode(name, input);
  if (options.session) {
    const key = profile.keys[options.session];
    const sig = await signAction(await importSeed(key.seed), sender, account.nonce, payload);
    return { body: submitBody(sender, account.nonce, assembleSessionSignature(key.publicKey, sig), payload), account };
  }
  const mode = options.guardian ? "guardian" : account.programmable ? "owner" : "legacy";
  const onChain = options.guardian ? account.programmable?.policy.recovery?.guardians : account.programmable?.policy.owners;
  const initial = sender === profile.uiAccount ? "ui" : "original";
  const policy = options.group ? threshold(profile, options.group) : onChain
    ? { threshold: onChain.threshold, members: onChain.members.map(m => toHex(Uint8Array.from(m))) } : threshold(profile, initial);
  const keys = Object.values(profile.keys).filter(k => policy.members.includes(k.publicKey)).slice(0, options.partial ? 1 : policy.threshold);
  const sigs = await Promise.all(keys.map(async k => [k.publicKey, await signAction(await importSeed(k.seed), sender, account.nonce, payload)]));
  let signature;
  if (options.partial || options.group) {
    const witness = multisigSignature(policy.threshold, policy.members.map(fromHex), sigs.map(([k, s]) => [fromHex(k), s]));
    signature = mode === "legacy" ? witness : `a7${mode === "guardian" ? "02" : "00"}${witness}`;
  } else {
    const response = await fetch(`${api}/multisig/assemble`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, nonce: account.nonce, threshold: policy.threshold, members: policy.members, payload: Array.from(payload),
        mode, signatures: sigs.map(([public_key, signature]) => ({ public_key, signature })) }) });
    if (!response.ok) throw new Error(`assembler: ${response.status} ${await response.text()}`);
    signature = (await response.json()).signature;
  }
  return { body: submitBody(sender, account.nonce, signature, payload), account };
}
async function transact(profile, sender, name, input, options = {}) {
  const { body, account } = await build(profile, sender, name, input, options);
  const base = options.rpc ?? api;
  const response = await fetch(`${base}/actions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const text = await response.text();
  const fileName = `${sender === profile.uiAccount ? "ui" : "test"}-last-action.json`;
  await jsonFile(fileName, body);
  let outcome;
  if (!response.ok) outcome = { status: "rejected", http: response.status, reason: text };
  else {
    for (let i = 0; i < 120; i++) {
      const result = await fetch(`${base}/actions/${body.signature}`);
      if (result.ok) {
        const status = await result.json();
        if (status.status === "confirmed" || status.status === "dropped") { outcome = status; break; }
      }
      await pause(250);
    }
    if (!outcome) throw new Error(`${name} never confirmed or dropped`);
  }
  if (options.reject) {
    assert.notEqual(outcome.status, "confirmed", `unexpected success: ${name}`);
    const after = await get(`/accounts/${sender}`, options.rpc ?? rpc);
    assert.equal(after.nonce, account.nonce, "a rejected action consumed a nonce");
    assert.equal(after.balance, account.balance, "a rejected action charged a fee");
  } else assert.equal(outcome.status, "confirmed", `${name}: ${JSON.stringify(outcome)}`);
  console.log(`${options.reject ? "EXPECTED FAILURE" : "PASS"} ${name}: ${JSON.stringify(outcome)}`);
  return outcome;
}
async function prepare() {
  if (existsSync(join(home, "profile.json"))) throw new Error(`already prepared: ${home}`);
  await mkdir(home, { recursive: true, mode: 0o700 });
  await mkdir(join(home, "keys"), { recursive: true, mode: 0o700 });
  const profile = { home, rpc, api, launchRpc, password, keys: {} };
  for (const [i, alias] of aliases.entries()) {
    const seed = (i + 1).toString(16).padStart(2, "0").repeat(32);
    const raw = publicKey(seed), address = encodeAddress(raw), pkcs8 = fromHex(`302e020100300506032b657004220420${seed}`);
    const keyFile = join(home, "keys", `${alias}.json`);
    await writeFile(keyFile, `${JSON.stringify(toKeyFile({ address, publicKey: toHex(raw), blob: await wrapPkcs8(pkcs8, password) }, "local-account-demo"), null, 2)}\n`, { mode: 0o600 });
    profile.keys[alias] = { address, publicKey: toHex(raw), seed, keyFile };
  }
  profile.testAccount = await multisigAddress(2, threshold(profile, "original").members.map(fromHex));
  profile.uiAccount = await multisigAddress(2, threshold(profile, "ui").members.map(fromHex));
  profile.asset = await deriveAssetRef(profile.testAccount, "manual_demo");
  for (const [name, enabled] of [["extensions", true], ["launch", false]]) {
    const basePath = join(home, name);
    await mkdir(basePath, { recursive: true, mode: 0o700 });
    const validators = JSON.parse(execFileSync(join(root, "target/debug/arxd"), ["keys", "--base-path", basePath, "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
    const accounts = Object.fromEntries(Object.values(profile.keys).map(k => [k.address, { balance: 100000000000, nonce: 0, identity_hash: null }]));
    for (const address of [profile.testAccount, profile.uiAccount]) accounts[address] = { balance: 1000000000000, nonce: 0, identity_hash: null };
    await jsonFile(`${name}.json`, { genesis_format: "plain", height: 0, chain_name: `account-demo-${name}`, accounts, validators, boot_nodes: [],
      attestor_admin: profile.testAccount,
      params: { block_interval_secs: 1, epoch_length: 100, min_validator_set: 1, max_validator_set: 16, validator_attestation_required: false,
        reward_per_block: 0, weight_fee: 1000, challenge_window_blocks: 2, account_extensions_enabled: enabled } });
  }
  await jsonFile("profile.json", profile);
  await jsonFile("ui-policy-input.json", { policy: policyFor(profile, "ui") });
  await jsonFile("ui-rotate-input.json", { owners: threshold(profile, "next") });
  await jsonFile("ui-enroll-proposal.json", { sender: profile.uiAccount, threshold: 2, members: threshold(profile, "ui").members,
    payload: { name: "setAccountPolicy", input: { policy: policyFor(profile, "ui") } } });
  await jsonFile("ui-rotate-proposal.json", { sender: profile.uiAccount, threshold: 2, members: threshold(profile, "ui").members, mode: "owner",
    payload: { name: "rotateAccountMembers", input: { owners: threshold(profile, "next") } } });
  console.log(JSON.stringify({ home, uiAccount: profile.uiAccount, testAccount: profile.testAccount, allowed: profile.keys.allowed.address,
    outsider: profile.keys.outsider.address, uiMembers: groups.ui.map(a => profile.keys[a].address), password }, null, 2));
}
async function test(profile) {
  const sender = profile.testAccount;
  assert.equal((await get(`/accounts/${sender}`)).nonce, 0, "test requires the untouched automated account; the UI account is separate");
  const reports = [];
  const act = async (name, input, options = {}) => { reports.push({ name, outcome: await transact(profile, options.sender ?? sender, name, input, options) }); await jsonFile("test-report.json", reports); };
  const metadata = { asset_class: "bond", decimals: 0, required_claims: [], allowed_jurisdictions: null, max_supply: "1000000", metadata_uri: null, symbol: "MANUAL", name: "Manual demo asset" };
  await act("registerAsset", { assetId: "manual_demo", complianceRequired: false, metadata }, { partial: true, reject: true });
  await act("registerAsset", { assetId: "manual_demo", complianceRequired: false, metadata });
  await act("issueAsset", { asset: profile.asset, amount: "1000" });
  await act("registerAttestor", { attestor: profile.keys.allowed.address, name: "Local test provider", reason: "manual demo" });
  await act("freezeAsset", { asset: profile.asset, frozen: true, reason: "issuer freeze test" });
  await act("issuerForcedTransfer", { asset: profile.asset, from: sender, to: profile.keys.allowed.address, amount: "100", reason: "issuer forced transfer test" });
  await act("setAccountPolicy", { policy: policyFor(profile) });
  await act("rotateAccountMembers", { owners: threshold(profile, "next") });
  await act("transfer", { to: profile.keys.allowed.address, amount: "1" }, { group: "original", reject: true });
  await act("issueAsset", { asset: profile.asset, amount: "1" });
  await act("unfreezeAsset", { asset: profile.asset, frozen: false, reason: "rotated issuer test" });
  assert.equal((await get(`/assets/${profile.asset}`)).issuer, sender);
  let policy = fromNodePolicy((await get(`/accounts/${sender}`)).programmable.policy);
  policy.limits = [{ asset: "native", periodBlocks: "100000", amount: "80000000" }, { asset: { asset: profile.asset }, periodBlocks: "100000", amount: "100" }];
  await act("setAccountPolicy", { policy });
  await act("transfer", { to: profile.keys.allowed.address, amount: "60000000" });
  await act("transfer", { to: profile.keys.allowed.address, amount: "60000000" }, { reject: true });
  await act("transfer", { to: profile.keys.outsider.address, amount: "1" }, { reject: true });
  policy.limits[0].amount = "500000000";
  await act("setAccountPolicy", { policy });
  await act("transferAsset", { asset: profile.asset, to: profile.keys.allowed.address, amount: "60" });
  await act("transferAsset", { asset: profile.asset, to: profile.keys.allowed.address, amount: "60" }, { reject: true });
  policy.limits[0] = { asset: "native", periodBlocks: "8", amount: "30000000" };
  await act("setAccountPolicy", { policy });
  // Begin near the start of a window so the expected failure cannot race rollover.
  const start = (await get("/status")).height;
  await waitHeight((Math.floor(start / 8) + 1) * 8);
  await act("transfer", { to: profile.keys.allowed.address, amount: "10000000" });
  await act("transfer", { to: profile.keys.allowed.address, amount: "10000000" }, { reject: true });
  const counter = (await get(`/accounts/${sender}`)).programmable.counters.find(c => c.asset === "Native");
  await waitHeight((counter.window + 1) * 8);
  await act("transfer", { to: profile.keys.allowed.address, amount: "10000000" });
  policy.limits[0] = { asset: "native", periodBlocks: "100000", amount: "500000000" };
  await act("setAccountPolicy", { policy });
  const session = alias => ({ publicKey: profile.keys[alias].publicKey, asset: "native", allowance: "1000000", recipients: [profile.keys.allowed.address], expiresAt: String((Date.now() / 1000 | 0)) });
  const limited = session("session"); limited.expiresAt = String((await get("/status")).height + 120);
  await act("addSessionKey", { session: limited });
  await act("transfer", { to: profile.keys.allowed.address, amount: "1000000" }, { session: "session" });
  await act("transfer", { to: profile.keys.allowed.address, amount: "1000000" }, { session: "session", reject: true });
  await act("rotateAccountMembers", { owners: threshold(profile, "original") }, { session: "session", reject: true });
  const expiring = session("expiring-session"); expiring.expiresAt = String((await get("/status")).height + 6);
  await act("addSessionKey", { session: expiring });
  await waitHeight(Number(expiring.expiresAt));
  await act("transfer", { to: profile.keys.allowed.address, amount: "0" }, { session: "expiring-session", reject: true });
  const revoked = session("revocable-session"); revoked.expiresAt = String((await get("/status")).height + 120);
  await act("addSessionKey", { session: revoked });
  await act("revokeSessionKey", { publicKey: revoked.publicKey });
  await act("transfer", { to: profile.keys.allowed.address, amount: "0" }, { session: "revocable-session", reject: true });
  await act("startAccountRecovery", { owners: threshold(profile, "original") }, { guardian: true });
  await act("executeAccountRecovery", {}, { guardian: true, reject: true });
  await act("cancelAccountRecovery", {});
  await act("executeAccountRecovery", {}, { guardian: true, reject: true });
  await act("startAccountRecovery", { owners: threshold(profile, "original") }, { guardian: true });
  const pending = (await get(`/accounts/${sender}`)).programmable.pending_recovery;
  await waitHeight(pending.execute_after);
  await act("executeAccountRecovery", {}, { guardian: true });
  const recovered = await get(`/accounts/${sender}`);
  assert.equal(recovered.programmable.policy.sessions.length, 0);
  assert.equal(recovered.programmable.pending_recovery, null);
  assert.deepEqual(recovered.programmable.policy.owners.members.map(m => toHex(Uint8Array.from(m))), threshold(profile, "original").members);
  await act("transfer", { to: profile.keys.allowed.address, amount: "0" }, { group: "next", reject: true });
  await act("setAccountPolicy", { policy: policyFor(profile, "ui") }, { sender: profile.uiAccount, rpc: launchRpc, reject: true });
  await jsonFile("test-report.json", reports);
  console.log(`All ${reports.length} live checks passed. UI account remains unenrolled. Report: ${home}/test-report.json`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "prepare") return prepare();
  const profile = await readProfile();
  if (command === "browser-key") {
    const key = profile.keys[args[0] ?? "ui-a"]; assert.ok(key, "unknown key alias");
    const file = JSON.parse(await readFile(key.keyFile, "utf8"));
    const { version, kdf, iterations, salt, iv, ciphertext } = file;
    const body = { address: file.address, publicKey: file.publicKey, blob: { version, kdf, iterations, salt, iv, ciphertext } };
    console.log(`(async () => { const r = await fetch('/api/registry/key', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(${JSON.stringify(body)}) }); console.log(r.status, await r.json()); if (r.ok) location.href = '/console/settings'; })();`);
    return;
  }
  if (command === "test") return test(profile);
  if (command === "status") { console.log(JSON.stringify({ main: await get("/status"), launch: await get("/status", launchRpc), uiAccount: profile.uiAccount,
    allowed: profile.keys.allowed.address, outsider: profile.keys.outsider.address, account: await get(`/accounts/${profile.uiAccount}`), password, home }, null, 2)); return; }
  const sender = profile.uiAccount;
  if (command === "ui-transfer") return transact(profile, sender, "transfer", { to: profile.keys[args[0] ?? "allowed"].address, amount: args[1] ?? "60000000" }, { reject: args.includes("--reject"), group: args.includes("--old-key") ? "ui" : undefined });
  if (command === "ui-rotate") return transact(profile, sender, "rotateAccountMembers", { owners: threshold(profile, "next") });
  if (command === "ui-reset-budget") {
    const account = await get(`/accounts/${sender}`); assert.ok(account.programmable, "enroll the UI account first");
    const policy = fromNodePolicy(account.programmable.policy);
    policy.limits = [{ asset: "native", periodBlocks: "100000", amount: "500000000" }];
    return transact(profile, sender, "setAccountPolicy", { policy });
  }
  if (command === "ui-launch-gate") return transact(profile, sender, "setAccountPolicy", { policy: policyFor(profile, "ui") }, { rpc: launchRpc, reject: true });
  if (command === "ui-add-session") {
    const session = { publicKey: profile.keys.session.publicKey, expiresAt: String((await get("/status")).height + Number(args[0] ?? "120")),
      asset: "native", allowance: args[1] ?? "1000000", recipients: [profile.keys.allowed.address] };
    await jsonFile("ui-session-input.json", { session });
    return transact(profile, sender, "addSessionKey", { session });
  }
  if (command === "ui-session-transfer") return transact(profile, sender, "transfer", { to: profile.keys[args[0] ?? "allowed"].address, amount: args[1] ?? "1000000" }, { session: "session", reject: args.includes("--reject") });
  if (command === "ui-revoke-session") return transact(profile, sender, "revokeSessionKey", { publicKey: profile.keys.session.publicKey });
  if (command === "ui-start-recovery") return transact(profile, sender, "startAccountRecovery", { owners: threshold(profile, "ui") }, { guardian: true });
  if (command === "ui-cancel-recovery") return transact(profile, sender, "cancelAccountRecovery", {});
  if (command === "ui-execute-recovery") return transact(profile, sender, "executeAccountRecovery", {}, { guardian: true, reject: args.includes("--reject") });
  if (command === "ui-wait-recovery") { const pending = (await get(`/accounts/${sender}`)).programmable.pending_recovery; assert.ok(pending, "no pending recovery"); console.log(await waitHeight(pending.execute_after)); return; }
  if (command === "ui-policy") { const account = await get(`/accounts/${sender}`); console.log(JSON.stringify(account.programmable, null, 2)); return; }
  throw new Error("use prepare|test|status|browser-key|ui-policy|ui-transfer|ui-rotate|ui-reset-budget|ui-launch-gate|ui-add-session|ui-session-transfer|ui-revoke-session|ui-start-recovery|ui-cancel-recovery|ui-wait-recovery|ui-execute-recovery");
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
