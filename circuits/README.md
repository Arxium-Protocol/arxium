# The Circuits (Business Logic)

Independently reusable business-logic modules. A "circuit" is Arxium's
equivalent of what Substrate calls a "pallet" or Cosmos calls a "module":
a self-contained unit that implements the logic for one piece of chain
behavior — today that means handling one payload variant for some chain,
but the shape generalizes to any discrete feature (identity, governance,
etc.) as the runtime grows. Circuits never know about `Action<P>` or any
chain's payload enum — they take plain values (`sender: &Address, nonce:
u64, ...`) and a lookup function. That's what lets a chain-specific
`dispatch` fn (owned by the chain, not by `core/executor`) call into a
circuit without the circuit needing generics or payload-shape knowledge.

## What lives here

| Crate               | Path                 | Responsibility                                                                                                                                                                                                                                                                            |
| ------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `circuit-account`   | `circuits/account`   | Plain transfer: `apply_transfer(lookup, sender, nonce, to, amount)`. Validates nonce and balance against current state, returns the resulting changes as an `AccountUpdates` (a `BatchWritable`, defined in `xc-storage`) — it does **not** write to the DB itself. The caller decides when to commit. |
| `circuit-rwa-asset` | `circuits/rwa-asset` | RWA chain logic: `apply_issue` (self-mint by the designated issuer) and `apply_compliant_transfer` (requires both sender and recipient have `AccountEntry.identity_hash` set — the KYC/allowlist marker — before delegating the actual balance/nonce math to `circuit_account::apply_transfer`). Proof that circuits compose: this crate reuses `circuit-account` rather than reimplementing transfer math. |

As new payload variants are added (by any chain), each gets its own
circuit here rather than growing an existing one into a catch-all.

## The shape every circuit follows

1. Take a lookup function for current account state (read-only — usually
   backed by `ArxiumDb`, but the executor may overlay it with an earlier
   action's not-yet-committed changes from the same block) and plain
   values for whatever the operation needs — never an `Action<P>` or a
   payload enum.
2. Validate against current state — nonce ordering, balances, compliance,
   whatever the specific operation requires. Return a typed error (via
   `thiserror`) on failure; never panic on bad input.
3. Return the _proposed_ state changes as a `BatchWritable`, without
   writing them. Committing is the caller's job, so a whole block's
   worth of changes can be batched together.
4. No networking, no RPC, no knowledge of which chain role is running,
   no knowledge of `Action<P>`/payload shape — a circuit only ever sees
   plain arguments and the DB handle it's given.

## Boundary rule

> **Does this need to know what role the node is playing to do its job?**

Circuits should almost always answer **no** — the whole point of a
circuit is that its logic (e.g. "how a transfer works") doesn't change
based on which chain role is running it. If you find a circuit needing
role awareness, that's a sign either the role check belongs in the
calling chain's `dispatch` fn (deciding _whether_ to call this circuit at
all), or the circuit is trying to do too much and should be split.

**Dependency direction:** circuits depend on `xc-primitives` and
`xc-storage` (from `core/`). Circuits do not depend on `arxd/`. Circuits
_can_ depend on each other when one composes another's logic (e.g.
`circuit-rwa-asset` depends on `circuit-account`) — that's preferred over
duplicating the underlying math. What circuits must not do is depend on
`core/executor` or any chain crate (`arxd/*`, `examples/*`) — the
dependency only ever flows circuit → circuit or circuit → `core/`, never
back up.

## For AI agents

If you're asked to implement handling for a new payload variant: add a
new crate here (`circuits/<name>`, package name `circuit-<name>`) taking
plain arguments (not `Action<P>`), wire its dispatch into the calling
chain's own `dispatch` fn (e.g. `arxd/node/src/payload.rs` for CoreChain,
`examples/toy-chain/src/main.rs` for the RWA chain) — not into
`core/executor`, which has no knowledge of payload types — and keep the
circuit itself free of role checks, networking, and direct DB writes —
return updates, don't apply them.
