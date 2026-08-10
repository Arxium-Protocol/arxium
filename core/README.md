# The Core SDK

Arxium's reusable SDK. Everything here is **role-agnostic**: no crate in
`core/` is allowed to know or care whether it's running as CoreChain, a
future Spoke Chain, or anything else. That's the one rule that defines
this directory — see "The boundary rule" below before adding anything.

## What lives here

| Crate           | Path              | Responsibility                                                                                                                                                                                                                                                                         |
| --------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xc-primitives` | `core/primitives` | Shared types: `Action<P>`, `Block<P>` (generic over a chain-specific payload type `P` — there is no shared payload enum), `Address`, `Snapshot`/`AccountEntry`, signing/verification, `NodeConfig`, deterministic proposer selection (`expected_proposer`). No I/O, no storage, no role knowledge — pure data + logic that operates only on its own arguments. |
| `xc-storage`    | `core/storage`    | `ArxiumDb`, a thin RocksDB wrapper. Owns key encoding (`account:<addr>`, `block:<height>`, `action:<sig>`, `meta:*`), the `BatchWritable` trait that lets other crates describe atomic writes without knowing anything about RocksDB itself, and `AccountUpdates` (the write-batch shape any account-touching circuit hands back).                                        |
| `xc-mempool`    | `core/mempool`    | `Mempool<P>`: an in-memory, capacity-bounded queue of `Action<P>`s, deduplicated by `(sender, nonce)`. It is deliberately dumb — it does not validate signatures or nonces against chain state. It trusts whatever handed it an `Action` already checked that.                               |
| `xc-executor`   | `core/executor`   | Takes a DB handle, a batch of `Action<P>`s, and a caller-supplied `dispatch` closure, verifies signatures, calls `dispatch` per action, and returns which ones actually applied plus their unwritten account updates. The dispatch table (which payload variant → which circuit call) is owned by the calling chain, not hardcoded here — that's what lets `arxd/node` and `examples/toy-chain` share this crate with completely different payload types. |

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
