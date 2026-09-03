# arx-verify

Standalone verifier for Arxium fault evidence artifacts. It depends only on
`xc-artifact` — no chain code, no storage, no network — so it builds and
runs on a machine that has never talked to an Arxium node.

## What it proves — and what it doesn't

Arxium validators write a signed JSON artifact whenever they observe a
fault:

- **Equivocation** — a validator double-signed two different blocks at the
  same height. `arx-verify` checks both block signatures and that they're
  from the same proposer at the same height, and reports the pubkey that's
  provably guilty.
- **Execution disagreement** — a validator's local execution disagreed
  with a proposed block's state root and it signed a dissent saying so.
  `arx-verify` checks the proposer's block signature and the voter's BLS
  signature over the dissent, and confirms the dissent actually targets
  the proposed block (via `header_commitment`).

`arx-verify` proves the artifact is internally consistent — the
signatures are real and they say what the artifact claims they say. It
does **not** prove:

- **That the artifact is about a chain you should care about.**
  `genesis_hash` is carried in the artifact but not checked against
  anything by this tool. Nothing stops someone from handing you a
  validly-signed artifact from a throwaway devnet and letting you assume
  it's about a chain you recognize. Check the artifact's `genesis_hash`
  against a genesis-hash registry you trust independently of this tool
  before treating a `VALID` verdict as meaning anything.
- **Who's at fault, for a disagreement.** An `UNRESOLVED` verdict means a
  genuine dispute happened between the two named parties — it does not
  mean either one did something wrong. Resolving that is a governance
  question, not something a signature check can answer.

## Install / build

From the workspace root:

```sh
cargo build --release -p arx-verify
# binary at target/release/arx-verify
```

## Usage

```sh
arx-verify <evidence.json>
```

Prints a verdict to stdout and exits `0` if the artifact verifies, `1`
otherwise (bad path, malformed JSON, or a signature/consistency check
that fails).

### `VALID` — equivocation, culprit identified

```sh
$ arx-verify examples/equivocation.json
VALID
fault: equivocation
genesis_hash: 0xa1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff
culpable_pubkey: 0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
```

### `UNRESOLVED` — execution disagreement, dispute confirmed but no culprit named

```sh
$ arx-verify examples/disagreement.json
UNRESOLVED
fault: execution_disagreement
genesis_hash: 0xa1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff
parties: 0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c, 0x957467ef01661798515186269581fd323fc8fd8fb05215d6944b2f2e742400c92778fe84fd1347b97f4159be4451966b
note: this artifact proves a proposer/validator execution disagreement, not who is at fault
```

Both sample artifacts under `examples/` are real — generated with the same
signing/verification code as production, just synthetic test keys, so
running `arx-verify` against them exercises the actual verify path rather
than hand-written JSON.

## Getting an artifact

A node writes each artifact it produces to its local evidence directory
and serves it over its own RPC:

- `GET /evidence` — list known artifact filenames on that node.
- `GET /evidence/{id}` — fetch one artifact's raw JSON.

Fetch it from there, check its `genesis_hash`, then run `arx-verify`
against the file.
