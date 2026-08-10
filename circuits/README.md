# The Circuits (Business Logic)

Independently reusable business-logic modules. A "circuit" is Arxium's
equivalent of what Substrate calls a "pallet" or Cosmos calls a "module":
a self-contained unit that implements the logic for one piece of chain
behavior — today that means handling one `ActionPayload` variant, but the
shape generalizes to any discrete feature (identity, governance, etc.) as
the runtime grows.

## What lives here

| Crate             | Path               | Responsibility                                                                                                                                                                                                                                                                            |
| ----------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `circuit-account` | `circuits/account` | Handles `ActionPayload::Transfer`. Validates nonce and balance against current state (`ArxiumDb::get_account`), and returns the resulting changes as an `AccountUpdates` (a `BatchWritable`) — it does **not** write to the DB itself. The caller (`xc-executor`) decides when to commit. |

As new `ActionPayload` variants are added, each gets its own circuit here
rather than growing `circuit-account` into a catch-all.

## The shape every circuit follows

1. Take a lookup function for current account state (read-only — usually
   backed by `ArxiumDb`, but the executor may overlay it with an earlier
   action's not-yet-committed changes from the same block) and the `Action`
   being applied.
2. Validate against current state — nonce ordering, balances, whatever
   the specific payload requires. Return a typed error (via `thiserror`)
   on failure; never panic on bad input.
3. Return the _proposed_ state changes as a `BatchWritable`, without
   writing them. Committing is the executor's job, so a whole block's
   worth of changes can be batched together.
4. No networking, no RPC, no knowledge of which chain role is running —
   a circuit only ever sees the `Action` and the DB handle it's given.

## Boundary rule

> **Does this need to know what role the node is playing to do its job?**

Circuits should almost always answer **no** — the whole point of a
circuit is that its logic (e.g. "how a transfer works") doesn't change
based on which chain role is running it. If you find a circuit needing
role awareness, that's a sign either the role check belongs in `arxd/`
(deciding _whether_ to call this circuit at all), or the circuit is
trying to do too much and should be split.

**Dependency direction:** circuits depend on `xc-primitives` and
`xc-storage` (from `core/`). Circuits do not depend on `arxd/` or on each
other — if two circuits need to share logic, that shared logic belongs in
`core/`, not in a dependency between circuits.

## For AI agents

If you're asked to implement handling for a new `ActionPayload` variant:
add a new crate here (`circuits/<name>`, package name `circuit-<name>`),
wire its dispatch into `arxd/executor`'s match on `ActionPayload`, and
keep the circuit itself free of role checks, networking, and direct DB
writes — return updates, don't apply them.
