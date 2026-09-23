import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encodeAddress, decodeAddress } from "./bech32.js";
import { Writer, fromHex, toHex } from "./bincode.js";
import * as actions from "./actions.js";
import { arxToIum, iumToArx } from "./amounts.js";
import { importSeed } from "./keys.js";

const ALICE = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";
const BOB = "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5";
assert.equal(toHex(new Writer().varint(250).bytes()), "fa");
assert.equal(toHex(new Writer().varint(251).bytes()), "fbfb00");
assert.equal(encodeAddress(decodeAddress(ALICE)), ALICE);
assert.equal(arxToIum("1.25"), 1_250_000_000n);
assert.equal(iumToArx(1_250_000_000n), "1.25");

type Fixture = { name: string; input: Record<string, unknown>; sender: string; nonce: number; payload: string; signing_bytes: string; signature: string };
type FixtureDocument = { private_key_seed: string; public_key: string; fixtures: Fixture[] };
const asBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;
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
console.log("sdk codec tests passed");
