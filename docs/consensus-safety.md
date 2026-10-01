# Consensus: rounds, locks and finality-gated production

Answers "can this chain fork under partition" and states the rules the code
enforces. Model: `n = 3f + 1` validators by voting power, at most `f`
Byzantine, quorum `2f + 1` (`QUORUM_POWER`). The voting protocol is
Tendermint's (Buchman, Kwon, Milosevic, *The latest gossip on BFT
consensus*, 2018), restated in this codebase's terms. It replaced a
single-phase protocol (rule "S2") that could leave a height permanently
uncertified (D-25; the history is in `docs/consensus-round-change.md`).

## 1. Commit levels

- **Provisional tip.** `accept_block` commits a valid block at `tip + 1`
  immediately (`core/executor`). It is served to peers and voted on. It can
  be *unwound* (`ArxiumDb::revert_to`) as long as it is above the finalized
  watermark.
- **Finalized.** A height is final when a quorum of that height's validator
  set has BLS-precommitted the same `(height, round, block_hash, ep)`
  (`arxd/finality::tally_vote` → `FinalityRecord`). The contiguous finalized
  watermark (`final_watermark`) is the irreversibility line: `revert_to`
  refuses to cross it. PoE calls this ATTESTED.
- **Settled (FINAL).** A certified block whose challenge window has closed
  with no upheld dispute: `height <= final_watermark -
  challenge_window_blocks` (`settled_height` in `/status`, `settlement` on
  each block). See §5.

Production waits for finality (N1 below), so the provisional tip is at most
one block above the watermark. **The provisional tip can change under
partition; the finalized chain cannot.** A partition that leaves neither
side a quorum finalizes nothing and produces nothing until it heals.

## 2. The protocol

Per height `h`, a validator votes only at `h = final_watermark + 1`, and in
rounds `r = 0, 1, …`. The round-`r` block is the one its eligible proposer
(`eligible_proposer(h, r)`) signs for round `r`; a block at `r > 0` carries
the `RoundCertificate` for `r − 1` (S3, unchanged).

Three signed votes, each tallied per `(height, round)`:

- **Prevote** `(h, r, block)`. A quorum of prevotes for one block at one
  round is a **lock** (`PolRecord`, Tendermint's "proof of lock").
- **Precommit** `(h, r, block, ep)`. A quorum at one round finalizes.
- **Round timeout** `(h, r, parent)`. A quorum is a `RoundCertificate`,
  which moves the height to round `r + 1`.

Validator rules (`arxd/finality`; the safety-critical ones are enforced
durably by `SignedVotes` before anything is signed):

- **V1.** At most one prevote and one precommit per `(h, r)`. Two different
  precommits is `PrecommitEquivocation`, slashed.
- **V2.** No prevote or precommit at `(h, r)` after signing a timeout for
  `(h, r)`, or after any vote at a later round of `h`.
- **V3.** A validator's **lock** is its latest precommit at `h`, `(lr,
  lv)`. It prevotes a block other than `lv` only with a lock (a quorum of
  prevotes) for that block at a round `vr` with `lr ≤ vr ≤ r`.
- **V4.** It precommits a block at round `r` only on a lock for that block at
  round `r`, and only once it holds and executed the block.
- **V5.** It prevotes, in the current round, the block of the highest lock at
  `h` if there is one, else the round's own block.
- **V6.** A round that runs `timeout_for(r)` (8s, growing with the round to
  40s) without finalizing gets a timeout vote. Signing it after prevoting or
  precommitting in the round is allowed; it ends the validator's votes in
  that round (V2).

Node rules:

- **N1.** A producer builds on a finalized parent only, never at a height
  locked on another block, and claims `(height, round)` in `signed_height`
  first. A later round of the same height is not equivocation
  (`submit_equivocation_evidence`, `xc_evidence::verify_equivocation`), so a
  proposer the rotation brings back proposes again.
- **N2.** The block held at `h` follows, in order: a finality certificate
  (`enforce_certificate`), the highest lock (the finality thread unwinds any
  other block and sync fetches the locked one), then a later round's block
  (dead-tip replacement, below).
- **N3.** `accept_block` refuses a block at `h` that contradicts a stored
  finality certificate or the highest lock there, and one from a round `h`
  already left that no lock names (`DeadRound`) — so sync can't hand back a
  dead tip this node just unwound.
- **N4.** A round certificate for the round of the block held at `h`, or a
  later-round block carrying one, unwinds it — unless it is locked
  (`unwind_dead_tip`, `supersede_dead_tip`).

## 3. Safety argument

Claim: two different blocks cannot both finalize at one height, under at
most `f` faults and with no timing assumption.

Suppose `B` finalizes at `(h, r)`: a quorum precommitted it, so by V4 a lock
for `B` at `r` exists, and at least `f + 1` honest validators precommitted
`B` at `r`, so are locked on `B` with `lr ≥ r` (V3 lets a lock move only to
a later round).

- **No lock on another block at `r`.** It would need a quorum of prevotes at
  `r` for `C ≠ B`; with the lock for `B` that is `f + 1` validators prevoting
  twice at `r`, one of them honest — against V1.
- **No lock on another block at any `r' > r`**, by induction on `r'`. A lock
  for `C` at `r'` needs a quorum of prevotes, which includes at least one of
  the `f + 1` locked honest validators. By V3 it prevoted `C` only with a lock
  for `C` at some `vr` with `r ≤ vr ≤ r'`. `vr < r'` contradicts the
  induction hypothesis. `vr = r'` means the lock for `C` at `r'` existed
  before any locked honest validator prevoted `C` at `r'`, so a quorum formed
  from the other validators alone — at most `2f` of the power, below quorum.

With no lock for any other block at a round `≥ r`, V4 means no honest
validator precommits another block at those rounds, so none can finalize.
A block finalizing at a round `< r` is excluded by the same argument with
the two blocks swapped. `ep` is part of the signed precommit, so two quorums
for the same hash with different execution outcomes never merge either.

What safety no longer depends on: round certificates. A timeout vote now
means only "this validator is done with the round" and can be signed after
precommitting, so a round-`r` certificate does not prove the round-`r` block
can't finalize — which is why N2/N4 keep a locked block through a round
change.

**Liveness.** Once the network is synchronous for long enough, the growing
round timeouts exceed the real message delay, every validator sees the same
highest lock and round (a validator re-sends its prevotes and timeout votes
every 4s until the height finalizes — past its own round certificate, and
reloaded from disk after a restart, since a peer that missed one can't form
the certificate from anything else), and
a round whose proposer is honest — or whose lock everyone holds — gets a
quorum of prevotes and then precommits. Sequential voting (only at
`final_watermark + 1`) plus N1 make the D-25 state impossible: nothing is
built or voted on top of a height that has not finalized.

**Accepted costs.** One more gossip hop per height (the prevote) before
finality. With 2 or 3 validators the quorum needs everyone, so any one slow
or offline validator stops finality — and, through N1, production — under
any protocol; mainnet needs at least 4 roughly equal validators.

## 4. What remains open

- `ep` disagreement (honest execution divergence) splits a round's votes and
  cannot be resolved by rounds — a determinism bug, surfaced as dissent and
  evidence, not something consensus should paper over.
- A chain whose registered BLS keys can't reach quorum finalizes nothing;
  there N1 does not wait for finality, so the chain keeps producing
  provisional blocks instead of halting before it can register keys.
- Monitoring: `arxium_finalized_height - arxium_final_watermark > 0` for 5
  minutes fires `ArxiumFinalityGap` (`monitoring/prometheus/alerts.yml`).
  Regression checks: `scripts/late-block-harness.sh` (D-25),
  `partition-heal-harness.sh`, `withholding-proposer-harness.sh`,
  `two-node-fault-harness.sh`.

## 5. The challenge window (execution disputes)

A certified block can still be wrong if enough of the set signed a bad
state root. Any validator that re-executes it and disagrees signs a
`BlockDivergence` artifact, and anyone can submit it
(`SubmitExecutionFault`) up to `challenge_window_blocks` after the block
(`ChainParams`, default 21,600 blocks = 12h at 2s; must stay below
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

An upheld dispute that names the proposer slashes no one at once: a
certified wrong root means at least 2/3 of the set signed it, which is
likelier a shared determinism bug than an attack. It writes
`DisputedBlockKey { height, header }` and an open-dispute row naming the
proposer and the challenger (who submitted the proof), and governance
classifies it later (Recovery, below). `DisputedBlockKey { height, header }`, where `header` is the sha256
of the disputed header's signing bytes: that block reports `settlement:
"disputed"` and never becomes FINAL. The key names the block, not the
height, because the culprit's block is often one the chain dropped (its
round timed out and another block was certified at that height), and that
other block must still settle. The chain does not unwind a certified
block on its own; what to do with the state after a disputed block is an
operator and governance decision (recovery, below).

Whoever submitted an upheld fault gets paid: for equivocation, and for a
dispute resolved as an attack, `challenger_reward_bps` of what was slashed
(default 5%, capped at 10% by `SetChainParams`); for a dispute resolved as
a bug, a `bounty` the resolution names, paid from the treasury. So an
outside Guard has a reason to submit and not only the dissenting validator. The
rest goes to the reward pool like any slash. Nothing is burned. An artifact
against an already-tombstoned validator slashes nothing and pays nothing.

`Fault::ActionDivergence` (one action, two separately claimed pre-states)
has no on-chain path. No node signs the per-action claims it needs, and
`BlockDivergence` covers the whole block from the pre-state the proposer
signed. `arx-verify` still checks it offline.

W = 12h. Optimistic rollups use ~7
days because a challenger has to get through a possibly censored L1; here
the evidence lands on this chain, where any one honest proposer includes
it, and dissenting validators submit within seconds.

### Recovery after an upheld dispute

**Rule: an upheld dispute pauses settlement, not the chain.** Blocks keep
being produced and users keep transacting. The dispute also writes
`DisputeOpenKey { height, header }`, and while any such key exists
`get_settled_height` is `min(watermark - window, lowest_open_dispute - 1)`,
so nothing from the bad block onward becomes `final` (the RPC `settlement`
field follows it). Those blocks read `attested`, which is exactly what the
challenge window already tells users. The chain never halts or rolls back
by itself.

**Detect.** The node logs `execution dispute upheld` at `error!` level, and
`/status` carries `open_dispute_height` (null when none). Alert on it being
non-null. There is no metrics endpoint in `arxd` yet; the log line and this
field are the hooks.

**Decide, by this criterion, fixed before an incident:**

- **A. Accept and correct (default).** Use it when the supply invariant and
  the validator-set invariant still hold after the disputed block.
  Validators propose `ResolveDispute { height, header, resolution: Accept,
  corrections }` (`corrections` = balances to set, empty if the difference is
  harmless) and vote it through like any proposal. Executing it deletes the
  open marker, applies the corrections, and settlement resumes. No history
  is rewritten.
- **B. Fork, rebasing instead of rolling back.** Use it only when an
  invariant is broken or the difference is too large to reason about.
  1. Operators halt the chain.
  2. Export the state at the disputed block's `parent_state_root`
     (`ArxiumDb::state_at(height - 1)`; undo records are kept for the whole
     challenge window plus 5,000 blocks, so this works for any dispute the
     chain can still uphold) and apply the disputed block correctly with the
     fixed binary.
  3. Replay the transactions from later blocks, in order, on the corrected
     state. Drop any that now fail and publish that list.
  4. Restart from the result as a new genesis that keeps the height. The
     old chain's open marker goes away with it, so no `ResolveDispute` is
     needed there; `Forked` exists to record it if the old chain stays up,
     and takes no corrections.

  This keeps most of up to 12h of user activity instead of discarding it.

**Undoing a tombstone.** If the dispute turns out to be a determinism bug,
the proposer should not stay banned. A `ReinstateValidator { validator }`
proposal deletes its `Tombstoned` status row, so it can `JoinValidator`
again with fresh stake (slashed stake is not returned). It rejects if the
validator is not tombstoned. Who is slashed in the first place is still open
(Trello 202).

**Classify the cause.** `ResolveDispute` carries `cause` and `bounty`.
Re-execute the disputed block with the canonical binary first.
`Bug` (version mismatch, determinism fault): nobody is slashed and the
challenger gets `bounty` from the treasury. `Attack` (a root no bug
explains): the proposer is slashed and tombstoned as an equivocator is and
the challenger gets the percentage reward; an attack verdict carries no
corrections and no bounty. Signers of the bad root are not penalised yet;
their precommits stay in the finality certificate as evidence.

**Who and when.** The validator set decides, through the ordinary proposal
and vote (`voting_period_blocks`). Settlement stays paused for as long as it
takes; nobody is promised finality for those blocks meanwhile.

**Dissenting nodes.** A node that re-executed and disagreed sits on
`local tip stuck` / `HaltBelowWatermark`. It probably still holds the correct
parent state, but do not depend on it: export from a node that has the undo
records, keep the dissenter's data directory for forensics, and re-sync it
from the resolved chain (path A) or the new genesis (path B).

**Storage cost.** Retaining undo records for the window is ~86k records,
each holding only the keys that block touched. `state_at` materialises the
whole state in memory, which is fine for a one-time recovery export.

Not built: automatic halting, automatic rollback, a rebase tool. Path B is
to be rehearsed once on devnet (force a bad root, uphold the dispute, export,
rebase, restart) and the tool written from what that needs.
