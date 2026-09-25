# Consensus: forks, rounds and finality-gated commit (B1c)

Answers "can this chain fork under partition", states the invariants the
code enforces, and records the B1c change that closed the liveness hole
behind the runbook's open question ("can an honest quorum recover from a
rejected proposal via round change"). Model: `n = 3f + 1` validators by
voting power, at most `f` Byzantine, quorum `2f + 1` (`QUORUM_POWER`).

## 1. Two commit levels

- **Provisional tip.** `accept_block` commits the first valid block it sees
  at `tip + 1` to storage immediately (`core/executor`). It is served to
  peers and built on. It can be *unwound* (`ArxiumDb::revert_to`) as long as
  it is above the finalized watermark.
- **Finalized.** A height is final when a quorum of that height's validator
  set has BLS-precommitted the same `(height, round, block_hash, ep)`
  (`arxd/finality::tally_vote` → `FinalityRecord`). The contiguous
  finalized watermark (`final_watermark`) is the irreversibility line:
  `revert_to` refuses to cross it, and it is the only correct answer to "is
  my transfer settled".

So: **the provisional tip can fork under partition; the finalized chain
cannot.** A partition that isolates fewer than `2f + 1` on either side
finalizes nothing until it heals; whichever side holds a quorum keeps
finalizing and the minority is unwound to the watermark on rejoin
(`arxd/network` divergence recovery, or `enforce_certificate` when it
tallies the majority's votes itself).

## 2. Safety argument

Invariants an honest validator keeps (`arxd/finality::spawn_finality`):

- **S1.** At most one precommit per `(height, round)`. Two precommits at the
  same `(height, round)` for different hashes is `PrecommitEquivocation` —
  provable from the two signatures, slashed.
- **S2.** Never sign a round-timeout vote for `(height, r)` after
  precommitting at `(height, r)`, and never precommit at `(height, r)` after
  signing a timeout for it.
- **S3.** A block at round `r > 0` is only valid with an embedded
  `RoundCertificate` for `r − 1` (quorum of timeout votes) —
  `accept_block::verify_round_certificate`, recomputable by any node from
  the block alone.

Claim: two different blocks cannot both finalize at one height.

- Same round: two certificates need `2f + 1` each, so `f + 1` validators
  voted both — at least one honest, contradicting S1.
- Different rounds `r < r'`: the round-`r'` block carries a certificate for
  round `r' − 1`. An honest signer of a timeout for round `k` was in round
  `k`, so had seen a certificate for `k − 1`; by induction a certificate for
  round `r` exists. Its `2f + 1` signers overlap the `2f + 1` precommitters
  of the round-`r` block in `f + 1`, at least one honest — contradicting S2.
  So no round-`r` block can have a finality certificate once round `r` is
  certified as timed out.

Hence at most one finalized block per height, under `≤ f` faults, with no
assumption about timing. `ep` (execution proof) is part of the signed vote,
so two quorums for the same hash with different execution outcomes never
merge either.

## 3. The liveness hole B1c closed

Before B1c, precommit votes did not carry a round and `my_votes` was keyed
by height alone: a validator that precommitted *any* block at `h` could
never vote at `h` again. With `n = 4`: proposer `P0` (Byzantine) sends a
valid `A@0` to `N1` only. `P0 + N1` vote `A` (2 < 3). `N2, N3` time out and,
with `P0` signing too, certify round 0. `N2` proposes `B@1`; `N2, N3` vote
it; `N1` holds `A` as its tip, rejects `B` as `NotNextHeight`, and could
not vote it anyway. `P0` withholds. `A` = 2 votes, `B` = 2 votes — the
height is stuck forever with a single faulty validator.

After B1c:

- Votes carry `round` (signed; `DOMAIN_PRECOMMIT` v3), tallies and
  equivocation are per `(height, round)` — S1 as stated above. `N1` may
  vote `B@1` after `A@0`: different round, not equivocation. Safe because
  the round-0 certificate `B` carries proves `A` can never finalize (§2).
- **Dead-tip replacement.** When a node holds an unfinalized tip at
  `(h, r)` and either (a) it persists a `RoundCertificate` for `(h, r)`
  (`tally_round_timeout`), or (b) a block arrives at height `h` with
  `round > r` and a valid embedded certificate (`accept_block`), the tip is
  dead — §2 says it cannot finalize — and is unwound to `h − 1` so the
  higher-round candidate can be committed and voted. A block at height `h`
  with `round ≤ r` is still rejected (`NotNextHeight`), and a finalized tip
  is never touched (`ContradictsCertificate` / the watermark floor).
- The producer likewise builds on `h − 1` at the certified round rather
  than on a dead tip, because the dead tip is gone before its next tick.

So `N1` unwinds `A` on seeing `B@1`'s certificate, commits `B`, votes it:
`N1, N2, N3` = 3, `B` finalizes. Exercised live by
`scripts/withholding-proposer-harness.sh`.

## 4. What remains provisional-only (accepted)

- `ep` disagreement (honest execution divergence) splits a round's votes
  and cannot be resolved by rounds — that is a determinism bug, surfaced
  as dissent / evidence, not something consensus should paper over.
- Round timeouts are wall-clock (`ROUND_TIMEOUT`); under asynchrony a round
  can time out although its block would have finalized. That costs a round,
  never safety (§2).
- Storage keeps one candidate per height (the tip), replacing it rather
  than holding a set. Holding several candidates buys nothing for safety
  and only matters if the same height flips repeatedly, which needs
  repeated timeouts — acceptable until measured otherwise.
