import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { decodePayload, encodeAddress, fromHex, toHex, toKeyFile, wrapPkcs8 } from "./index.js";

const vectors = JSON.parse(await readFile(new URL("../fixtures/account-policies.json", import.meta.url), "utf8"));
const dir = await mkdtemp(join(tmpdir(), "arx-policy-cli-"));
const run = promisify(execFile), password = "cli-integration-passphrase";
const server = createServer((request, response) => {
  response.setHeader("Content-Type", "application/json");
  if (request.url === "/genesis-hash") { response.end(JSON.stringify({ genesis_hash: `0x${vectors.genesis_hash}` })); return; }
  assert.equal(request.url, `/accounts/${vectors.sender}`);
  response.end(JSON.stringify({ nonce: vectors.nonce, programmable: { policy: { owners: { threshold: 2, members: vectors.members.members.map((m: string) => Array.from(fromHex(m))) } } } }));
});
await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
const port = (server.address() as { port: number }).port;
const cli = async (...args: string[]) => JSON.parse((await run(process.execPath, [new URL("./cli.js", import.meta.url).pathname, "--rpc", `http://127.0.0.1:${port}`, ...args], { env: { ...process.env, ARX_PASSPHRASE: password } })).stdout);
try {
  for (let i = 0; i < 2; i++) {
    const pkcs8 = Buffer.from(`302e020100300506032b657004220420${vectors.seeds[i]}`, "hex");
    const publicKey = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" })).export({ format: "jwk" });
    const raw = Buffer.from(publicKey.x!, "base64url");
    const file = toKeyFile({ address: encodeAddress(raw), publicKey: toHex(raw), blob: await wrapPkcs8(pkcs8, password) });
    await writeFile(join(dir, `member-${i}.json`), JSON.stringify(file), { mode: 0o600 });
  }
  const vector = vectors.fixtures.find((f: { name: string }) => f.name === "rotateAccountMembers");
  await writeFile(join(dir, "proposal.json"), JSON.stringify({ sender: vectors.sender, nonce: vectors.nonce,
    threshold: 2, members: vectors.members.members, mode: "owner", payload: { name: vector.name, input: vector.input } }));
  const request = await cli("multisig", "build", join(dir, "proposal.json"));
  assert.equal(request.payload, vector.payload);
  await writeFile(join(dir, "request.json"), JSON.stringify(request));
  const first = await cli("--key", join(dir, "member-0.json"), "multisig", "sign", join(dir, "request.json"));
  await writeFile(join(dir, "first.json"), JSON.stringify(first));
  const second = await cli("--key", join(dir, "member-1.json"), "multisig", "sign", join(dir, "first.json"));
  await writeFile(join(dir, "second.json"), JSON.stringify(second));
  const action = await cli("multisig", "combine", join(dir, "second.json"));
  assert.equal(action.signature, vector.signature);
  assert.deepEqual(action.payload, Array.from(fromHex(vector.payload)));
  assert.equal(action.sender, vectors.sender);
  assert.equal(action.nonce, vectors.nonce);
  console.log("CLI build → member sign → member sign → assemble passed");
  const key = ["--key", join(dir, "member-0.json"), "--nonce", "0", "sign"];
  const decoded = async (...args: string[]) => decodePayload(Uint8Array.from((await cli(...key, ...args)).payload));
  assert.deepEqual(await decoded("register-asset", "fund-a", "FUNDA", "Fund A", "0", "kyc", "CH,LI"), { name: "registerAsset", input: { assetId: "fund-a", complianceRequired: false,
    metadata: { asset_class: "other", decimals: 0, required_claims: ["kyc"], allowed_jurisdictions: ["CH", "LI"], max_supply: null, metadata_uri: null, symbol: "FUNDA", name: "Fund A" } } });
  assert.deepEqual(await decoded("issue-asset", "arxasset1x", "1000"), { name: "issueAsset", input: { asset: "arxasset1x", amount: "1000" } });
  assert.deepEqual(await decoded("transfer-asset", "arxasset1x", vectors.sender, "5"), { name: "transferAsset", input: { asset: "arxasset1x", to: vectors.sender, amount: "5" } });
  console.log("CLI register-asset / issue-asset / transfer-asset payloads passed");
  assert.deepEqual(await decoded("apply-attestor", "Arxium Bank", `${vectors.sender},${vectors.sender}`, "2", "ab12", "https://e.example"), { name: "applyAttestor", input: { name: "Arxium Bank", owners: [vectors.sender, vectors.sender], threshold: 2, evidenceHash: "ab12", evidenceUri: "https://e.example" } });
  assert.deepEqual(await decoded("block-attestor"), { name: "blockAttestor", input: {} });
  console.log("CLI apply-attestor / block-attestor payloads passed");
  const who = vectors.sender;
  assert.deepEqual(await decoded("propose-add-attestor", who, "Arxium Bank", `${who},${who}`, "2", "ab12", "https://e.example", "add the bank"), { name: "submitProposal", input: { action: { kind: "addAttestor", attestor: who, name: "Arxium Bank", owners: [who, who], threshold: 2, evidenceHash: "ab12", evidenceUri: "https://e.example" }, description: "add the bank" } });
  assert.deepEqual(await decoded("propose-remove-attestor", who, "bad actor"), { name: "submitProposal", input: { action: { kind: "removeAttestor", attestor: who }, description: "bad actor" } });
  assert.deepEqual(await decoded("propose-unblock-attestor", who, "key rotated"), { name: "submitProposal", input: { action: { kind: "unblockAttestor", attestor: who }, description: "key rotated" } });
  assert.deepEqual(await decoded("vote", "7", "yes"), { name: "voteProposal", input: { proposal: "7", approve: true } });
  assert.deepEqual(await decoded("execute-proposal", "7"), { name: "executeProposal", input: { proposal: "7" } });
  console.log("CLI governance payloads passed");
} finally {
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  await rm(dir, { recursive: true, force: true });
}
