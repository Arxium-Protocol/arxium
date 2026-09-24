# @arxium-protocol/sdk

TypeScript SDK and `arx` CLI for the private Arxium network. It has zero runtime dependencies and requires Node 20 or later. The SDK uses WebCrypto Ed25519 and also runs in browsers and Workers.

## Install

Until mainnet the package isn't on any registry. Consumers commit the packed tarball and depend on it as a file:

```sh
# release checks (what .github/workflows/sdk.yml runs)
cd Arxium && cargo test -p arxd-runtime writes_typescript_signed_action_fixtures && git diff --exit-code sdk/ts/fixtures
cd sdk/ts && npm test
# pack into the consumer, e.g. Console
npm pack --pack-destination ../../../Console/vendor
```

```json
"@arxium-protocol/sdk": "file:vendor/arxium-protocol-sdk-0.1.0.tgz"
```

For a new version: bump `version` here, pack, update the file name in the consumer's `package.json`, run `npm install`, and delete the old tarball.

## SDK quickstart

```ts
import { ArxiumRpc, encodeTransfer, arxToIum } from "@arxium-protocol/sdk";

const rpc = new ArxiumRpc({ rpc: "https://node.example", token: process.env.ARX_TOKEN });
const payload = encodeTransfer("arx1...", arxToIum("1.5"));
```

All token amounts are `bigint`: `1 ARX = 1_000_000_000 IUM`.

### Multisig senders

An M-of-N address (up to 16 members) is derived from its policy. Each member signs the action exactly as a single-key sender would. You then combine exactly `threshold` of those signatures:

```ts
const sender = await multisigAddress(2, [pkA, pkB, pkC]);          // member order doesn't matter
const sigA = await signAction(keyA, sender, nonce, payload);       // on A's machine
const sigC = await signAction(keyC, sender, nonce, payload);       // on C's machine
const signature = multisigSignature(2, [pkA, pkB, pkC], [[pkA, sigA], [pkC, sigC]]);
await rpc.submit(submitBody(sender, nonce, signature, payload));
```

Set the resulting address as an admin role (genesis or `SetAdmin`) or as an asset issuer (`TransferIssuer`). To rotate members, move the role to a new multisig address.

## Key files

`arx` reads and writes Console's encrypted export JSON unchanged:

```json
{
  "address": "arx1...",
  "publicKey": "...",
  "version": 1,
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt": "...",
  "iv": "...",
  "ciphertext": "...",
  "network": "arx-devnet"
}
```

`network` is a display label. It is not a signing domain. The CLI verifies that a decrypted private key matches `address` and `publicKey`.

Set `ARX_PASSPHRASE` for non-interactive use. Otherwise `arx` prompts on a terminal. A non-terminal invocation without it exits with status 2.

## CLI

Global configuration: `--rpc`, `--token`, `--key`, and `--json` have `ARX_RPC`, `ARX_TOKEN`, and `ARX_KEY` environment equivalents.

```sh
arx keys new
arx keys import --file arxium-devnet-key-abc.json
printf '%s' "$SEED_HEX" | arx keys import
arx keys show --key arxium-devnet-key-abc.json   # no passphrase needed

arx sign transfer arx1recipient 1500000000 --key key.json             # nonce fetched from --rpc
arx sign transfer arx1recipient 1500000000 --key key.json --nonce 7   # fully offline
arx submit signed-action.json
arx send transfer arx1recipient 1500000000 --key key.json

arx query status
arx query account arx1address
arx query block 42
arx query block 0xblockhash
arx query action signature
arx query validators
arx query finality
arx query search arx1address
arx verify signature
```

Supported signed actions are `transfer`, `stake`, `unstake`, `join-validator`, `leave-validator`, `register-bls-key`, `authorize-operator`, `revoke-operator`, `grant-attestation`, and `revoke-attestation`. Amount arguments are raw IUM integers.
