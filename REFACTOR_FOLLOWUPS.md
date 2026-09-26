# Node bootstrap review: open follow-ups

Items left open after the node bootstrap review cards were implemented on
2026-09-26. Each section names the Trello card and the commit that closed it.
Everything listed here is deliberately out of scope for that card.

## 152: Atomic genesis install (`d2fb005`)
Card: https://trello.com/c/vRgOd2xN

- **Existing half-initialized DBs are not repaired.** A node that already hit
  the crash (snapshot written, BLS keys missing) still boots with no finality
  keys for its genesis validators. It needs a data-dir wipe. A boot-time check
  for "initialized, but a genesis validator with a `bls_pubkey` in the spec has
  no registered key" would find it automatically.
- **No crash-injection test.** The new test covers "bad key → nothing written".
  Nothing kills the process between writes, because it's one write now. Add one
  only if genesis ever goes back to more than one write.

## 167: `NodeConfig::offline()` (`623d9fa`)
Card: https://trello.com/c/DlJGJOjj

- `RunArgs::into_config` (`arxd/node/src/cli.rs`) still builds `NodeConfig` by
  hand. That is intentional: every field comes from a CLI arg. A new field
  still has to be added in two places (`offline` and `into_config`), but the
  compiler enforces both.

## 168: Split `spawn_subsystems` (`4c3db37`)
Card: https://trello.com/c/IF96Egmh

- **No unit tests for the new pieces.** The card's point was that the parts
  can now be tested separately (`spawn_evidence`, `spawn_finality_bridges`,
  `spawn_rpc`, `build_on_block`), but none were added. `build_on_block` is
  the best first candidate: accept, routine reject, and forged-signature
  returns `true`.
- **`scripts/two-node-fault-harness.sh` fails on `main`**, before and after the
  refactor. Two checks fail: "node 0's stake was not zeroed" and "node 0 never
  reverted". Honest nodes do write evidence artifacts, so the problem is
  between the artifact and an on-chain slash. Tracked as its own task.
- `spawn_subsystems` still takes 9 arguments, which is the clippy threshold.
  A `SubsystemInputs` struct would be the next step if it grows.

## 169: `cmd_prune` reports what `db.prune` did (`2f77574`)
Card: https://trello.com/c/sOd3wUYh

- The CLI prints the actual cutoff but doesn't say when the finalized
  watermark clamped it below the requested one. Print both if operators get
  confused.
- The old message said "superseded validator-set snapshots" were pruned. They
  never were (`validator_set:` rows are merkleized and kept on purpose). The
  message is fixed, and nothing is missing here.
- Existing ponytail in `ArxiumDb::prune`: `action:{signature}` replay-index
  entries still point at pruned heights.

## 170: `keys --stake` default (`d27e85b`)
Card: https://trello.com/c/NSEQYMTB

- The default is the compile-time `DEFAULT_MIN_VALIDATOR_STAKE`, not the
  target chain's configured `min_stake`. `arxd keys` doesn't know which chain
  the entry is for. If chain specs start overriding the minimum, add a
  `--chain` option to `keys` and default to that chain's value.

## 171: Fault-injection guards (`48d19e7`)
Card: https://trello.com/c/McuZkDDF

- **Env knobs have no unit test.** Setting env vars in tests is `unsafe` and
  racy, so they are covered only by the harnesses
  (`withholding-proposer-harness.sh` PASS). The `--inject-fault-at-height`
  refusal has a unit test.
- The CLI knob (`--inject-fault-at-height`) stays outside the `ENV_KNOBS`
  table because it arms a `OnceLock`, not an env var the subsystem reads
  itself.
- The arming warning's fields changed from `peers=` / `secs=` / `height=` to
  `var=` / `value=`. No script greps for them today.
