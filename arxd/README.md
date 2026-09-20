# Arxium Daemon (arxd)

The concrete node daemon. This is where `core/`'s role-agnostic building
blocks get assembled into an actual running Arxium node, and where
everything that _does_ need to know what the node is doing lives.

`arxd` follows the `<chain>d` daemon naming convention (like `geckod`-style
binaries). It is a single binary that can play any chain role — there is no
separate binary per role.

## What lives here

| Path | Responsibility |
| --- | --- |
| `arxd/src/main.rs` | Binary entrypoint. Sets up tracing/logging, calls `arxd_node::run::<CoreChainRuntime>()`. Nothing else — keep this file thin. |
| `arxd/node/` | The orchestration crate (`arxd-node`), generic over `ChainRuntime` so `examples/toy-chain` reuses it whole. Owns the produce loop and role decision (`lib.rs`, `produce.rs`), subsystem wiring (`components.rs`), the clap surface (`cli.rs`), the `arxd <subcommand>` handlers (`commands.rs`) and validator key management (`validator.rs`). The only crate allowed to decide "what role am I" and act on it. |
| `arxd/runtime/` | CoreChain's `ChainRuntime` (`arxd-runtime`): the payload enum (`payload.rs` — `ActionPayload`, `ChainAction`/`ChainBlock`; variant order is the wire format), the dispatch table, staking/asset/identity/governance state transitions, metering, and the proof-backed fault adjudicator `arx-verify` re-exports. The only place that decides what a CoreChain `ActionPayload::Transfer` means. |
| `arxd/genesis/` | `arxd-genesis`: BLS validator registration and the Plain/Raw `ChainSpec` a node boots from. Shared by `arxd-node`, `arxd-runtime` and `tools/spec-builder`. |
| `arxd/network/` | `arxd-network`: libp2p transport, mDNS and bootnode discovery, gossipsub for action/block/precommit propagation, `request_response` block and snapshot sync, and the sync protocol's wire types (`wire.rs`). Generic over the chain's payload type `P`. |
| `arxd/finality/` | `arxd-finality`: signs a BLS precommit for each observed block, tallies peer precommits against the validator set at that height, and writes a finality record once an aggregate reaches 2/3+1. |

Equivocation detection (`xc-evidence`), the RPC server (`xc-rpc`) and chain-spec
parsing (`xc-chain-spec`) live under `core/`: none of them needs chain or role
knowledge, only the payload type `P` as a generic. `cli` and the P2P wire types
went the other way — they were split out for external consumers that no longer
exist, so they are back inside the crates that use them.

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
