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
| `arxd/node/`       | The orchestration crate (`node`). Owns the CLI (`cli.rs`), genesis bootstrap (`genesis.rs`), the block-production loop and role decision (`lib.rs`), validator key management (`validator.rs`), the RPC ingest server (`rpc.rs`), and CoreChain's own payload type + dispatch table (`payload.rs`, public — `ActionPayload`, `ChainAction`/`ChainBlock` type aliases, `dispatch`). This is the only crate allowed to decide "what role am I" and act on it, and the only place that decides what a CoreChain `ActionPayload::Transfer` means.        |
| `arxd/runtime/`    | Reserved for CoreChain's actual runtime responsibilities as they get built out — validator set management, state root registry, conflict resolution, slashing. Not yet a real crate (no `Cargo.toml`, not a workspace member) — currently just a placeholder.                                                         |

`xc-executor` (batch dispatch of `Action`s to `circuits/*`) used to live
here but moved to `core/executor/` — its signature (DB handle + actions in,
applied actions + updates out) never needed to know which chain/role was
running it. `examples/toy-chain` is what proved that: it pulls in
`xc-executor` unmodified with zero `arxd` dependency.

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
(`node` depends on `executor`), but nothing in `core/` may depend back
into `arxd/`.

## Current pipeline (as of the R4 hardening pass)

```
RPC (POST /actions) → Mempool → produce_block → execute_actions → circuits/* → ArxiumDb
```

Note: as of this writing, signature/nonce validation happens inside
`execute_actions` at block-production time, not at the RPC boundary. The
target design (per the R4 plan) is to validate at the RPC boundary before
an `Action` ever enters the mempool — check `rpc.rs::submit_action` to see
whether that's landed yet before assuming either way.

## For AI agents

This is the layer where "which genesis file," "how do I handle this role,"
and "what does CoreChain actually do" questions get answered. If you're
asked to add role-specific behavior and you're currently looking at a file
under `core/`, that's the wrong file — come here instead, and prefer
putting the decision in `node::run()` over threading a role enum through
every function signature.
