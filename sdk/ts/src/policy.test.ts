import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { assemblePolicySignature, assembleSessionSignature, decodePayload, encodePayload, importSeed, signAction, signingBytes, toHex, fromHex, verifyPolicySignature, verifySignedAction, submitBody, type AccountPolicy, type DecodedPayload, type ThresholdPolicy } from "./index.js";

const vectors = JSON.parse(readFileSync(new URL("../fixtures/account-policies.json", import.meta.url), "utf8")) as {
  genesis_hash: string; sender: string; nonce: number; policy: AccountPolicy; members: ThresholdPolicy; seeds: string[];
  fixtures: { name: DecodedPayload["name"]; input: Record<string, any>; payload: string; signing_bytes: string; signature: string; mode: "owner" | "guardian" }[];
};
const genesis = fromHex(vectors.genesis_hash);
const pks = vectors.seeds.map(seed => {
  const publicKey = createPublicKey(createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${seed}`, "hex"), format: "der", type: "pkcs8" })).export({ format: "jwk" });
  return Buffer.from(publicKey.x!, "base64url").toString("hex");
});
for (const fixture of vectors.fixtures) {
  const decoded = { name: fixture.name, input: fixture.input };
  const bytes = encodePayload(decoded);
  assert.equal(toHex(bytes), fixture.payload, `${fixture.name} Rust payload`);
  assert.deepEqual(decodePayload(bytes), decoded);
  const message = signingBytes(genesis, vectors.sender, vectors.nonce, bytes);
  assert.equal(toHex(message), fixture.signing_bytes, `${fixture.name} Rust signing envelope`);
  const sigs = await Promise.all(vectors.seeds.slice(0, 2).map(async (seed, i) => [pks[i], await signAction(await importSeed(seed), genesis, vectors.sender, vectors.nonce, bytes)] as [string, string]));
  assert.equal(assemblePolicySignature(fixture.mode, vectors.members, sigs), fixture.signature, `${fixture.name} Rust witness`);
  assert.equal(await verifyPolicySignature(vectors.policy, fixture.signature, message), fixture.mode);
  assert.equal(await verifySignedAction(submitBody(vectors.sender, vectors.nonce, fixture.signature, bytes), genesis, vectors.policy), true);
  assert.equal(await verifySignedAction(submitBody(vectors.sender, vectors.nonce, fixture.signature, bytes), genesis), false, "historical stateful verification cannot guess policy");
  assert.equal(await verifyPolicySignature(vectors.policy, fixture.signature, signingBytes(genesis, vectors.sender, vectors.nonce + 1, bytes)), null);
  assert.throws(() => assemblePolicySignature(fixture.mode, vectors.members, [sigs[0], sigs[0]]), /distinct/);
  assert.throws(() => decodePayload(Uint8Array.from([...bytes, 0])), /trailing/);
}
const sessionSeed = "06".repeat(32), payload = encodePayload({ name: "transfer", input: { to: vectors.policy.sessions[0].recipients[0], amount: "7" } });
const signature = assembleSessionSignature(vectors.policy.sessions[0].publicKey, await signAction(await importSeed(sessionSeed), genesis, vectors.sender, 0, payload));
assert.equal(await verifyPolicySignature(vectors.policy, signature, signingBytes(genesis, vectors.sender, 0, payload)), "session");
assert.equal(await verifyPolicySignature({ ...vectors.policy, sessions: [] }, signature, signingBytes(genesis, vectors.sender, 0, payload)), null);
assert.throws(() => encodePayload({ name: "setAccountPolicy", input: { policy: { ...vectors.policy, owners: { ...vectors.members, members: [...vectors.members.members].reverse() } } } }), /sorted/);
assert.equal(toHex(encodePayload({ name: "cancelAccountRecovery", input: {} })), "2805");
console.log("programmable account Rust/TypeScript vectors passed");
