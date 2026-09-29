# Consensus: forks, rounds and finality-gated commit (B1c)

Answers "can this chain fork under partition", states the invariants the
code enforces, and records the B1c change that closed the liveness hole
behind the runbook's open question ("can an honest quorum recover from a
rejected proposal via round change"). Model: `n = 3f + 1` validators by
voting power, at most `f` Byzantine, quorum `2f + 1` (`QUORUM_POWER`).

## 1. Commit levels

- **Provisional tip.** `accept_block` commits the first valid block it sees
  at `tip + 1` to storage immediately (`core/executor`). It is served to
  peers and built on. It can be *unwound* (`ArxiumDb::revert_to`) as long as
  it is above the finalized watermark.
- **Finalized.** A height is final when a quorum of that height's validator
  set has BLS-precommitted the same `(height, round, block_hash, ep)`
  (`arxd/finality::tally_vote` → `FinalityRecord`). The contiguous
  finalized watermark (`final_watermark`) is the irreversibility line:
  `revert_to` refuses to cross it. PoE calls this ATTESTED.
- **Settled (FINAL).** A certified block whose challenge window has closed
  with no upheld dispute: `height <= final_watermark -
  challenge_window_blocks` (`settled_height` in `/status`, `settlement` on
  each block). This is the answer to "is my transfer settled". See §5.

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

**Open liveness gap (D-25), not accepted.** S2 can leave a round with
neither kind of quorum: some validators precommitted its block, others
(which got it late) had already timed it out, and neither side may sign the
other vote. The height never certifies while later heights do, so
`final_watermark` stops for good. Reproduced by
`scripts/late-block-harness.sh`, alerted on as `ArxiumFinalityGap`. The
proposed fix is in `docs/consensus-round-change.md`.

## 5. The challenge window (execution disputes)

A certified block can still be wrong if enough of the set signed a bad
state root. Any validator that re-executes it and disagrees signs a
`BlockDivergence` artifact, and anyone can submit it
(`SubmitExecutionFault`) up to `challenge_window_blocks` after the block
(`ChainParams`, default 86,400 blocks = 48h at 2s; must stay below
`unbonding_blocks`, checked at `SetChainParams`). After that the block is
FINAL and no longer open to one.

Adjudication is a deterministic replay of `accept_block` from proofs alone
(`arxd/runtime/src/adjudicate.rs`), so every node reaches the same verdict:

- **Pre-state.** The block header signs `parent_state_root`, and
  `accept_block` rejects a block whose value isn't its parent's
  `state_root`. The dissenter supplies proofs against it, never the root
  itself, so an honest proposer can't be framed with an invented pre-state.
- **All three phases.** Matured unbonding (`UnbondingDueKey(height)`), every
  action, and the seal (reward, downtime slash, epoch boundary over
  `ValidatorCandidatesKey`) are point reads, so all of them replay. Neither
  step scans the database any more.
- **Verdict.** The side whose root matches the replay is cleared. A root
  nobody's replay produces, or a block carrying an action honest nodes
  reject, names the proposer. A replay that needs state the proofs don't
  cover is a `Disagreement`: nobody is slashed on a guess.

An upheld dispute that names the proposer slashes and tombstones it and
writes `DisputedBlockKey { height, header }`, where `header` is the sha256
of the disputed header's signing bytes: that block reports `settlement:
"disputed"` and never becomes FINAL. The key names the block, not the
height, because the culprit's block is often one the chain dropped (its
round timed out and another block was certified at that height), and that
other block must still settle. The chain does not unwind a certified
block on its own; what to do with the state after a disputed block is an
operator and governance decision.

Whoever submitted an upheld fault (this action or
`SubmitEquivocationEvidence`) gets `challenger_reward_bps` of what was
slashed (default 5%, capped at 10% by `SetChainParams`), so an outside
Guard has a reason to submit and not only the dissenting validator. The
rest goes to the reward pool like any slash. Nothing is burned. An artifact
against an already-tombstoned validator slashes nothing and pays nothing.

`Fault::ActionDivergence` (one action, two separately claimed pre-states)
has no on-chain path. No node signs the per-action claims it needs, and
`BlockDivergence` covers the whole block from the pre-state the proposer
signed. `arx-verify` still checks it offline.

W = 48h follows CometBFT's default evidence age. Optimistic rollups use ~7
days because a challenger has to get through a possibly censored L1; here
the evidence lands on this chain, where any one honest proposer includes
it, and dissenting validators submit within seconds.
