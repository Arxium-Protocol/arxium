import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encodeAddress, decodeAddress, decodeAssetRef, deriveAssetRef } from "./bech32.js";
import { Writer, asBuffer, fromHex, toHex } from "./bincode.js";
import * as actions from "./actions.js";
import { arxToIum, iumToArx } from "./amounts.js";
import { PKCS8_ED25519_PREFIX, generateKey, importSeed, isKeyFile, rewrapKey, toKeyFile, unlockKey, verifyKeyFile, wrapPkcs8 } from "./keys.js";
import { ArxiumRpc, verifySignedAction } from "./rpc.js";

const ALICE = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";
const BOB = "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5";
assert.equal(toHex(new Writer().varint(250).bytes()), "fa");
assert.equal(toHex(new Writer().varint(251).bytes()), "fbfb00");
assert.equal(encodeAddress(decodeAddress(ALICE)), ALICE);
assert.equal(arxToIum("1.25"), 1_250_000_000n);
assert.equal(iumToArx(1_250_000_000n), "1.25");

type Fixture = { name: string; input: Record<string, unknown>; sender: string; nonce: number; payload: string; signing_bytes: string; signature: string };
type MultisigFixture = { threshold: number; member_seeds: string[]; members: string[]; signers: number[]; sender: string; nonce: number; to: string; amount: string; signature: string; asset_ref: string };
type FixtureDocument = { private_key_seed: string; public_key: string; fixtures: Fixture[]; multisig: MultisigFixture };
const golden = JSON.parse(readFileSync(new URL("../fixtures/signed-actions.json", import.meta.url), "utf8")) as FixtureDocument;
const encode = (fixture: Fixture): Uint8Array => {
  const input = fixture.input as Record<string, any>;
  switch (fixture.name) {
    case "transfer": return actions.encodeTransfer(input.to, BigInt(input.amount));
    case "joinValidator": return actions.encodeJoinValidator(input.validator, BigInt(input.stake), Uint8Array.from(input.blsPubkey), Uint8Array.from(input.blsPop));
    case "leaveValidator": return actions.encodeLeaveValidator(input.validator);
    case "stake": return actions.encodeStake(input.validator, BigInt(input.amount));
    case "unstake": return actions.encodeUnstake(input.validator, BigInt(input.amount));
    case "registerBlsKey": return actions.encodeRegisterBlsKey(input.validator, Uint8Array.from(input.pubkey), Uint8Array.from(input.pop));
    case "authorizeOperator": return actions.encodeAuthorizeOperator(input.operator);
    case "revokeOperator": return actions.encodeRevokeOperator();
    case "grantAttestation": return actions.encodeGrantAttestation(input.subject, input.hash, input.topics, input.jurisdiction);
    case "revokeAttestation": return actions.encodeRevokeAttestation(input.subject);
    case "registerAsset": return actions.encodeRegisterAsset(input.assetId, input.complianceRequired, input.metadata);
    case "issueAsset": return actions.encodeIssueAsset(input.asset, BigInt(input.amount));
    case "transferAsset": return actions.encodeTransferAsset(input.asset, input.to, BigInt(input.amount));
    case "freezeAsset": case "unfreezeAsset": return actions.encodeFreezeAsset(input.asset, input.frozen, input.reason);
    case "burnAsset": return actions.encodeBurnAsset(input.asset, BigInt(input.amount));
    case "setHolderFrozen": return actions.encodeSetHolderFrozen(input.asset, input.holder, input.frozen);
    case "lockHolderAmount": case "unlockHolderAmount": return actions.encodeLockHolderAmount(input.asset, input.holder, BigInt(input.amount), input.lock);
    case "issuerForcedTransfer": return actions.encodeIssuerForcedTransfer(input.asset, input.from, input.to, BigInt(input.amount), input.reason);
    case "recoverHolder": return actions.encodeRecoverHolder(input.asset, input.lost, input.replacement);
    case "issueAssetTo": return actions.encodeIssueAssetTo(input.asset, input.to, BigInt(input.amount));
    default: throw new Error(`unsupported fixture encoder: ${fixture.name}`);
  }
};
const privateKey = await importSeed(golden.private_key_seed);
const publicKey = await crypto.subtle.importKey("raw", asBuffer(fromHex(golden.public_key)), "Ed25519", false, ["verify"]);
for (const fixture of golden.fixtures) {
  const payload = encode(fixture);
  const signing = actions.signingBytes(fixture.sender, fixture.nonce, payload);
  assert.equal(toHex(payload), fixture.payload, `${fixture.name} payload`);
  assert.equal(toHex(signing), fixture.signing_bytes, `${fixture.name} signing bytes`);
  assert.equal(await actions.signAction(privateKey, fixture.sender, fixture.nonce, payload), fixture.signature, `${fixture.name} signature`);
  assert.equal(await crypto.subtle.verify("Ed25519", publicKey, asBuffer(fromHex(fixture.signature)), asBuffer(signing)), true, `${fixture.name} signature verifies`);
}
{
  const ms = golden.multisig, members = ms.members.map(fromHex), payload = actions.encodeTransfer(ms.to, BigInt(ms.amount));
  assert.equal(await actions.multisigAddress(ms.threshold, [...members].reverse()), ms.sender, "multisig address");
  assert.equal(await deriveAssetRef(ms.sender, "gold"), ms.asset_ref, "multisig issuer asset ref");
  const sigs = await Promise.all(ms.signers.map(async (i) => [members[i], await actions.signAction(await importSeed(ms.member_seeds[i]), ms.sender, ms.nonce, payload)] as [Uint8Array, string]));
  assert.equal(actions.multisigSignature(ms.threshold, members, sigs.reverse()), ms.signature, "multisig witness");
  const signed = actions.submitBody(ms.sender, ms.nonce, ms.signature, payload);
  assert.equal(await verifySignedAction(signed), true, "multisig verifies");
  assert.equal(await verifySignedAction({ ...signed, nonce: ms.nonce + 1 }), false, "multisig bound to nonce");
  assert.equal(await verifySignedAction({ ...signed, signature: actions.multisigSignature(ms.threshold, members, sigs.slice(0, 1)) }), false, "multisig below threshold");
}
console.log("sdk codec tests passed");

// --- ported from Console's lib/codec/codec.test.mts when Console moved onto this package
const widths: [bigint, string][] = [
  [0n, "00"], [250n, "fa"], [251n, "fbfb00"], [65535n, "fbffff"], [65536n, "fc00000100"],
  [4294967295n, "fcffffffff"], [4294967296n, "fd0000000001000000"],
  [2n ** 64n - 1n, "fdffffffffffffffff"], [2n ** 64n, "fe00000000000000000100000000000000"],
  [2n ** 128n - 1n, "fe" + "ff".repeat(16)],
];
for (const [value, hex] of widths) assert.equal(toHex(new Writer().varint(value).bytes()), hex, `varint ${value}`);
assert.throws(() => new Writer().varint(2n ** 128n));
assert.throws(() => new Writer().varint(-1n));
assert.equal(toHex(new Writer().option<string[]>([], (w, v) => w.vec(v, (ww, s) => ww.string(s))).bytes()), "0100", "Some([]) is not None");
assert.equal(new Writer().raw(new Uint8Array(200_000)).bytes().length, 200_000, "raw() takes large payloads");
assert.throws(() => decodeAddress(ALICE.slice(0, -1) + (ALICE.endsWith("z") ? "q" : "z")), /checksum/);
assert.throws(() => decodeAddress("bc1" + ALICE.slice(4)));
// AssetRef::derive(ALICE, "gold"), pinned in core/primitives/src/asset_ref.rs.
const ALICE_GOLD = "arxasset1z8d4jt8yt0xtjm6lvk8umc9relegrwq4xu928eqxyjfcsnjuex6qe873qa";
assert.equal(await deriveAssetRef(ALICE, "gold"), ALICE_GOLD);
assert.notEqual(await deriveAssetRef(BOB, "gold"), ALICE_GOLD);
assert.throws(() => decodeAssetRef(ALICE), /invalid asset ref/);

// --- key files: rewrap, Console export shape, tamper detection
{
  const generated = await generateKey("first passphrase!");
  const rewrapped = await rewrapKey(generated.blob, "first passphrase!", "second passphrase!");
  const key = await unlockKey(rewrapped, "second passphrase!");
  await assert.rejects(unlockKey(rewrapped, "first passphrase!"), /wrong passphrase/);
  const file = toKeyFile({ ...generated, blob: rewrapped });
  assert.deepEqual(Object.keys(file), ["address", "publicKey", "version", "kdf", "iterations", "salt", "iv", "ciphertext", "network"], "Console export field order");
  assert.ok(isKeyFile(file));
  await verifyKeyFile(file, key);
  assert.equal(isKeyFile({ ...file, address: BOB }), false, "address that isn't the publicKey's is rejected");
  await assert.rejects(verifyKeyFile({ ...file, publicKey: toHex(decodeAddress(BOB)), address: BOB }, key), /does not match/);
  // `arx keys import` wraps a pooled Node Buffer (a view into a shared 8 KB pool): it must still unlock.
  const pooled = Buffer.from(PKCS8_ED25519_PREFIX + golden.private_key_seed, "hex");
  assert.notEqual(pooled.buffer.byteLength, pooled.length, "test needs a pooled Buffer");
  const seedKey = await unlockKey(await wrapPkcs8(pooled, "pw"), "pw");
  assert.equal(await actions.signAction(seedKey, golden.fixtures[0].sender, golden.fixtures[0].nonce, fromHex(golden.fixtures[0].payload)), golden.fixtures[0].signature);
}

// --- RpcClient calls fetch unbound: browsers and Workers throw "Illegal invocation" otherwise
{
  const realFetch = globalThis.fetch;
  globalThis.fetch = function (this: unknown) { if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation"); return Promise.resolve(new Response('{"status":"dropped","reason":"x"}')); } as typeof fetch;
  assert.deepEqual(await new ArxiumRpc({ rpc: "http://node" }).action("ab"), { status: "dropped", reason: "x" });
  globalThis.fetch = realFetch;
}
console.log("sdk key and rpc tests passed");
