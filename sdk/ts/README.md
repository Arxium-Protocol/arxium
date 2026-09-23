# @arxium-protocol/sdk

TypeScript SDK and `arx` CLI for the private Arxium network. It has zero runtime dependencies and requires Node 20 or later. The SDK uses WebCrypto Ed25519 and also runs in browsers and Workers.

## Install

Create `.npmrc` with a GitHub Packages token that has `read:packages` access to `Arxium-Protocol`:

```ini
@arxium-protocol:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Then install the private package:

```sh
npm install @arxium-protocol/sdk
```

## SDK quickstart

```ts
import { ArxiumRpc, encodeTransfer, arxToIum } from "@arxium-protocol/sdk";

const rpc = new ArxiumRpc({ rpc: "https://node.example", token: process.env.ARX_TOKEN });
const payload = encodeTransfer("arx1...", arxToIum("1.5"));
```

All token amounts are `bigint`: `1 ARX = 1_000_000_000 IUM`.

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
arx keys show --key arxium-devnet-key-abc.json

arx sign transfer arx1recipient 1500000000 --key key.json
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
