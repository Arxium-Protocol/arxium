# The Core SDK

Arxium's reusable SDK. Everything here is **role-agnostic**: no crate in
`core/` is allowed to know or care whether it's running as CoreChain, a
future Spoke Chain, or anything else. That's the one rule that defines
this directory — see "The boundary rule" below before adding anything.

## What lives here

| Crate           | Path              | Responsibility                                                                                                                                                                                                                                                                         |
| --------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xc-primitives` | `core/primitives` | Shared types: `Action`, `ActionPayload`, `Block`, `Address`, `Snapshot`/`AccountEntry`, signing/verification, `NodeConfig`, deterministic proposer selection (`expected_proposer`). No I/O, no storage, no role knowledge — pure data + logic that operates only on its own arguments. |
| `xc-storage`    | `core/storage`    | `ArxiumDb`, a thin RocksDB wrapper. Owns key encoding (`account:<addr>`, `block:<height>`, `action:<sig>`, `meta:*`) and the `BatchWritable` trait that lets other crates describe atomic writes without knowing anything about RocksDB itself.                                        |
| `xc-mempool`    | `core/mempool`    | `Mempool`: an in-memory, capacity-bounded queue of `Action`s, deduplicated by `(sender, nonce)`. It is deliberately dumb — it does not validate signatures or nonces against chain state. It trusts whatever handed it an `Action` already checked that.                               |

## The boundary rule

Before adding a function, type, or crate here, ask:

> **Does this need to know what role the node is playing to do its job?**

- **No** → it belongs in `core/`. Example: hashing a block, encoding a
  `Snapshot` to bincode, opening a RocksDB handle, queueing an `Action`.
- **Yes** → it does not belong here. Example: which genesis JSON file to
  load, how to handle a specific `ActionPayload` variant's business logic
  beyond generic dispatch, validator-set / slashing decisions. Those live
  in `arxd/` (orchestration) or `circuits/` (business logic).

**Enforced dependency direction:** `arxd` depends on `core`, never the
reverse. `core` crates do not depend on `arxd`, `circuits`, or each other's
callers — check the `[dependencies]` block of any `core/*` crate before
merging a change that points back up the stack.

## Terminology

What other chains call a "transaction," Arxium calls an **Action**
(`xc_primitives::Action` / `ActionPayload`). This is intentional and
consistent across all crates, comments, logs, and docs — don't reintroduce
"transaction" / "tx" naming inside `core/`.

## For AI agents

If you're generating or modifying code in this directory: treat any
`if role == ...` branch, any hardcoded chain name, or any dependency on
`arxd`/`circuits` as a sign the code is in the wrong place. Stop and move
the role-specific part up to `arxd/` instead of adding a conditional here.
