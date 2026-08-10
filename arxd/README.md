# Arxium Daemon (arxd)

The concrete node daemon. This is where `core/`'s role-agnostic building
blocks get assembled into an actual running Arxium node, and where
everything that _does_ need to know what the node is doing lives.

`arxd` follows the `<chain>d` daemon naming convention (like `geckod`,
`polkadotd`-style binaries). It is a single binary that can play any chain
role — there is no separate binary per role.

## What lives here

| Path               | Responsibility                                                                                                                                                                                                                                                                                                        |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `arxd/src/main.rs` | Binary entrypoint. Sets up tracing/logging, calls `node::run()`. Nothing else — keep this file thin.                                                                                                                                                                                                                  |
| `arxd/node/`       | The orchestration crate (`node`). Owns the block-production loop and role decision (`lib.rs`), validator key management (`validator.rs`), and CoreChain's own payload type + dispatch table (`payload.rs`, public — `ActionPayload`, `ChainAction`/`ChainBlock` type aliases, `dispatch`). This is the only crate allowed to decide "what role am I" and act on it, and the only place that decides what a CoreChain `ActionPayload::Transfer` means.        |
| `arxd/runtime/`    | Reserved for CoreChain's actual runtime responsibilities as they get built out — validator set management, state root registry, conflict resolution, slashing. Not yet a real crate (no `Cargo.toml`, not a workspace member) — currently just a placeholder.                                                         |

`cli.rs`, `genesis.rs`, and `rpc.rs` used to live here but moved to
`core/cli`, `core/genesis`, and `core/rpc` — none of them, once written,
turned out to need chain/role knowledge: `Cli` is generic node-operator
config, genesis bootstrap only needed the embedded JSON string as a
parameter, and the RPC server only needed the payload type `P` as a
generic instead of CoreChain's concrete `ActionPayload`. Same story as
`xc-executor` before them — proven generic by making `examples/toy-chain`
use the mechanism (`Mempool<P>`, `Action<P>`) even though it doesn't wire
up its own RPC server today.

## The boundary rule

Same question as `core/`, answered the other way:

> **Does this need to know what role the node is playing to do its job?**

If yes, it belongs somewhere under `arxd/`. Role is decided **once**, at
the top, in `node::run()` / `Cli::into_config()` — as a config value. It
must not leak down as `if role == CoreChain` branches inside functions
like `execute_block`, `produce_block`, or the mempool. If you find
yourself adding a role check deep inside a function, that function
either needs the role passed in explicitly as a parameter at its call
site, or the branching belongs at the orchestration layer in
`arxd/node/`, not buried inside it.

**Enforced dependency direction:** `arxd` depends on `core` (and
`circuits`), never the reverse. `arxd` crates may depend on each other
(`arxd` depends on `node`), but nothing in `core/` may depend back into
`arxd/`.

## Current pipeline (as of the R4 hardening pass)

```
RPC (POST /actions) → Mempool → produce_block → execute_actions → circuits/* → ArxiumDb
```

Signature and stale-nonce validation happen at the RPC boundary
(`core/rpc`'s `submit_action`) before an action ever enters the mempool —
`execute_actions` still re-verifies the signature (defense in depth
against a mempool populated some other way) and is the only place that
catches insufficient-balance, since balance can still change between
submission and the action's turn in a block.

## For AI agents

This is the layer where "which genesis file," "how do I handle this role,"
and "what does CoreChain actually do" questions get answered. If you're
asked to add role-specific behavior and you're currently looking at a file
under `core/`, that's the wrong file — come here instead, and prefer
putting the decision in `node::run()` over threading a role enum through
every function signature.
