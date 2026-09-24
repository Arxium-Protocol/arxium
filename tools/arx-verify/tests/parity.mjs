// Run after build-web.sh: node tools/arx-verify/tests/parity.mjs <wasm-dir> <cli-binary>
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';

const [dir, binary] = process.argv.slice(2);
if (!dir || !binary) throw new Error('usage: node parity.mjs <wasm-dir> <cli-binary>');
const moduleText = await readFile(resolve(dir, 'arx_verify.js'), 'utf8');
const wasm = await import(`data:text/javascript;base64,${Buffer.from(moduleText).toString('base64')}`);
wasm.initSync({ module: await readFile(resolve(dir, 'arx_verify_bg.wasm')) });

for (const name of ['equivocation', 'disagreement']) {
  const file = resolve(import.meta.dirname, '../examples', `${name}.json`);
  const json = await readFile(file, 'utf8');
  const result = JSON.parse(wasm.verify_evidence(json));
  const cli = execFileSync(resolve(binary), [file], { encoding: 'utf8' }).trim().split('\n');
  assert.equal(result.status, cli[0], name);
  assert.equal(result.fault, cli[1].slice('fault: '.length), name);
  assert.equal(result.genesis_hash, cli[2].slice('genesis_hash: '.length), name);
  if (result.status === 'VALID') {
    assert.equal(result.culpable_pubkey, cli[3].slice('culpable_pubkey: '.length), name);
  } else {
    assert.equal(result.parties.join(', '), cli[3].slice('parties: '.length), name);
    assert.equal(result.note, cli[4].slice('note: '.length), name);
  }
  // A modified signed payload must be rejected identically by both paths.
  const tampered = json.replace(/"artifact_version": \d+/, '"artifact_version": 99');
  assert.notEqual(tampered, json, 'sample format changed');
  const invalid = JSON.parse(wasm.verify_evidence(tampered));
  const temp = await mkdtemp(resolve(tmpdir(), 'arx-verify-parity-'));
  let cliInvalid;
  try {
    const tamperedFile = resolve(temp, `${name}.json`);
    await writeFile(tamperedFile, tampered);
    cliInvalid = spawnSync(resolve(binary), [tamperedFile], { encoding: 'utf8' });
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
  assert.equal(cliInvalid.status, 1);
  assert.equal(invalid.status, 'INVALID');
  assert.equal(invalid.error, cliInvalid.stdout.trim().slice('INVALID: '.length));
  console.log(`${name}: ${result.status}; tampered: INVALID`);
}

// Exercise the second WASM export and its shared parse/error path too.
const badProof = JSON.parse(wasm.verify_state_proof('{"proof":{}}'));
assert.equal(badProof.status, 'INVALID');
assert.match(badProof.error, /not a state-proof response/);
