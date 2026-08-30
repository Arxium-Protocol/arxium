# The Core SDK

Arxium's reusable SDK. Everything here is **role-agnostic**: no crate in
`core/` is allowed to know or care whether it's running as CoreChain, a
future Spoke Chain, or anything else. That's the one rule that defines
this directory — see "The boundary rule" below before adding anything.

## What lives here

| Crate           | Path              | Responsibility                                                                                                                                                                                                                                                                         |
| --------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xc-primitives` | `core/primitives` | Shared types: `Action<P>`, `Block<P>` (generic over a chain-specific payload type `P` — there is no shared payload enum), `Address`, `Snapshot`/`AccountEntry`, signing/verification, `NodeConfig`, deterministic proposer selection (`expected_proposer`). No I/O, no storage, no role knowledge — pure data + logic that operates only on its own arguments. |
| `xc-storage`    | `core/storage`    | `ArxiumDb`, a thin RocksDB wrapper split into column families (`meta`, `blocks`, `accounts`, `validators` — see `cf_for_key`). Owns key encoding (`account:<addr>`, `block:<height>`, `action:<sig>`, `block_hash:<hash>`, `meta:*`), the `BatchWritable` trait that lets other crates describe atomic writes without knowing anything about RocksDB itself, and `AccountUpdates` (the write-batch shape any account-touching circuit hands back). Explorer-facing reads (`get_block_range`, `get_block_height_by_hash`) are plain point lookups, not a real scan — CoreChain's single proposer means heights commit sequentially with no gaps and no forks, so there's no reorg-handling or backfill pipeline to build. Per-address action history is served by NodeIndexer, not this crate — see `../STORAGE.md`. |
| `xc-mempool`    | `core/mempool`    | `Mempool<P>`: an in-memory, capacity-bounded queue of `Action<P>`s, deduplicated by `(sender, nonce)`. It is deliberately dumb — it does not validate signatures or nonces against chain state. It trusts whatever handed it an `Action` already checked that.                               |
| `xc-executor`   | `core/executor`   | Takes a DB handle, a batch of `Action<P>`s, and a caller-supplied `dispatch` closure, verifies signatures, calls `dispatch` per action, and returns which ones actually applied plus their unwritten account updates. The dispatch table (which payload variant → which circuit call) is owned by the calling chain, not hardcoded here — that's what lets `arxd/node` and `examples/toy-chain` share this crate with completely different payload types. |
| `xc-cli`        | `core/cli`        | The shared `Cli` arg struct (`--base-path`, `--port`, `--validator`, `--rpc-token`, `--rpc-bind`) → `NodeConfig`. Every field here is generic node-operator config, not chain business logic — a chain that needs its own extra flags wraps this rather than forking it. |
| `xc-chain-spec` | `core/chain-spec` | `PresetRegistry` (embedded-preset lookup), `resolve_chain_spec` (registry-first, path-fallback `--chain` resolution), `load_or_init_snapshot(base_path, embedded_json)` (caches a chain's genesis `Snapshot` to a per-node bincode file after first parsing it from JSON). Only the generic lookup/cache mechanics live here — the embedded JSON itself, and the concrete Plain/Raw `ChainSpec` a chain actually boots from, are chain-specific and stay with the caller (`arxd/genesis`, `arxd/node/specs/devnet.json`). |
| `xc-rpc`        | `core/rpc`        | `spawn_http_ingest<P>`: the HTTP ingest server (`POST /actions`, `GET /accounts/:address`, `GET /accounts/:address/actions`, `GET /actions/:signature`, `GET /blocks`, `GET /blocks/:height`, `GET /blocks/by-hash/:hash`, `GET /search`, `GET /status`) with bearer auth and per-IP rate limiting, generic over the chain's payload type `P`. Knows how to move `Action<P>` in and out of JSON and the mempool; never knows what a payload variant means. |

## The boundary rule

Before adding a function, type, or crate here, ask:

> **Does this need to know what role the node is playing to do its job?**

- **No** → it belongs in `core/`. Example: hashing a block, encoding a
  `Snapshot` to bincode, opening a RocksDB handle, queueing an `Action`.
- **Yes** → it does not belong here. Example: which genesis JSON file to
  load, what a chain's payload enum's variants mean, validator-set /
  slashing decisions, which circuit a payload variant dispatches to.
  Those live in `arxd/` or `examples/*` (orchestration + dispatch table)
  or `circuits/` (business logic).

**Enforced dependency direction:** `arxd` depends on `core`, never the
reverse. `circuits/` is reusable the same way `core/` is — a chain's own
crate (e.g. `arxd/node`, `examples/toy-chain`) depending on a `circuits/*`
crate is fine. `core/executor` itself has no `circuits/*` dependency — it
takes a `dispatch` closure from the caller instead, so it never needs to
know which circuits exist. What `core/` crates must never depend on is
`arxd` or each other's callers — check the `[dependencies]` block of any
`core/*` crate before merging a change that points back up the stack.

## Terminology

What other chains call a "transaction," Arxium calls an **Action**
(`xc_primitives::Action<P>`). Each chain defines its own payload type `P`
(e.g. `arxd/node`'s `ActionPayload`, `examples/toy-chain`'s `RwaPayload`) —
this is intentional and consistent across all crates, comments, logs, and
docs — don't reintroduce "transaction" / "tx" naming inside `core/`.

## For AI agents

If you're generating or modifying code in this directory: treat any
`if role == ...` branch, any hardcoded chain name, or any dependency on
`arxd`/`circuits` as a sign the code is in the wrong place. Stop and move
the role-specific part up to `arxd/` instead of adding a conditional here.
