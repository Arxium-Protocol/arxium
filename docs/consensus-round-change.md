# Round change with locks (D-25)

Status: **implemented** (2026-09-29). The rules as built are in
`docs/consensus-safety.md` §2–3; this file keeps the reasoning for the
change. Decisions taken against §7 below:

1. In-house, not Malachite: the rules fit the existing heights, rounds,
   round certificates and BLS aggregation with one new vote type, so the
   spike's integration cost would have been larger than the change.
2. Pipelining depth **0**, not 1: a producer builds only on a finalized
   parent. Finality lands well inside a 2s slot, so block time barely moves,
   and nothing is ever built on a height that might not certify.
3. Mainnet: at least 4 roughly equal validators (§6), unchanged.

Two things differ from the draft below. A lock needs no POL certificate
inside the block (§3.1): each node forms locks from the prevotes it tallies,
and every validator prevotes the highest lock it knows, so no proposer has
to re-propose. And a proposer's slashing protection is per (height, round),
so the rotation can bring it back to a height it already signed.

The reproduction, `scripts/late-block-harness.sh`, failed before the change
and must pass after it.

## 1. The problem

At `(h, r)` one validator can precommit the round's block while another,
which has not received it, signs a round-timeout vote. S2 then forbids
either of them from signing the other kind of vote for that round. If
neither kind reaches quorum, round `r` is stuck for good:

- no finality certificate for the block (not enough precommits), and
- no `RoundCertificate` to move to `r + 1` (not enough timeouts).

The producer keeps building on the uncertified block, later heights
certify, and `final_watermark` (so also `settled_height`) never moves past
`h − 1` again. That is what happened on the old devnet at 5627 (A-29,
`Arxium-Ops/docs/a29-finality-gap.md`). With two validators, each holding
half the power, one late delivery is enough.

Monitoring: `arxium_finalized_height - arxium_final_watermark > 0` for 5
minutes fires `ArxiumFinalityGap` (`monitoring/prometheus/alerts.yml`).

## 2. Why the current rules can't be patched

Today each height has one voting phase (precommit) and safety rests on S2.
A single voting phase can't give both safety and liveness at `n = 3f + 1`
when network delays are unbounded. Known "fast" single-phase protocols need
about `5f` validators (FaB Paxos: `5f + 1`). The patches we considered all
fail one way or the other:

| Option | Result |
| --- | --- |
| Relax S2: let precommitters also time out | Unsafe. The next proposer can't tell whether the old block already has a hidden quorum, so two blocks can finalize at one height. |
| Mixed certificate (precommits + timeouts ≥ quorum ⇒ round dead) | Unsafe with Byzantine signers: `f + 1` timeouts don't prove an honest validator is among them. |
| Count a child's certificate for its parent, and forbid a precommitter from later timing out an ancestor | Safe, but OVH (the late validator) must then also refuse `h + 1`, and finality halts completely in the D-25 case. |
| Forbid building on an uncertified parent | The stuck round still never resolves: a full chain halt instead of a silent gap. |

Protocols that are both safe and live at `3f + 1` add a second voting phase
and a **lock**: Tendermint (prevote/precommit), and the HotStuff family.
Arxium already has Tendermint's structure — heights with rounds, round
certificates, replacing a dead tip — so Tendermint is the closest fit.

## 3. Proposed protocol

Reference: Buchman, Kwon, Milosevic, *The latest gossip on BFT consensus*
(2018, arXiv:1807.04938). The rules below are that algorithm, restated in
this codebase's terms. Quorum and power arithmetic are unchanged
(`QUORUM_POWER`, `quorum_reached`).

Per validator, per height `h`, durable in `SignedVotes` (written before any
signature, like today's claims):

- `locked = (round, block_hash)` or none
- `valid = (round, block_hash)` or none — the latest block this node saw
  get a quorum of prevotes

### 3.1 Propose

The round-`r` proposer (`eligible_proposer`, unchanged) proposes `valid`'s
block if it has one, otherwise a fresh block. A re-proposed block carries
`pol_round` and a **POL certificate**: an aggregate BLS signature over a
quorum of prevotes for it at `pol_round`. As with S3's embedded
`RoundCertificate`, `accept_block` verifies it from the block alone.

### 3.2 Prevote (new)

On a valid proposal `B` at `(h, r)`, prevote `B` if any of these hold:

- not locked, or locked on `B`, or
- `B` carries a POL at `pol_round` with `locked.round ≤ pol_round < r`.

Otherwise prevote nil. With no proposal after the propose timeout, prevote
nil.

### 3.3 Precommit (changed)

A validator precommits only after seeing prevotes from a quorum — not on
`BlockObserved` as today:

- a quorum of prevotes for `B` at `(h, r)`: set `locked = valid = (r, B)`
  and precommit `B`;
- a quorum of nil prevotes: precommit nil;
- a quorum of mixed prevotes and the prevote timeout expires: precommit nil.

A quorum of precommits for `B` at any round writes the `FinalityRecord`,
exactly as today. `ep` stays inside the signed precommit.

### 3.4 Round change (S2 removed)

After precommitting (a block or nil), a validator may sign the round-timeout
vote for `(h, r)` once `ROUND_TIMEOUT` passes. The existing
`RoundTimeoutVote` / `RoundCertificate` machinery and S3 stay. What changes
is that safety no longer depends on "never both"; it depends on the lock.
The dead-tip unwind stays: a certificate for round `r` still means "move
on". But the round-`r` block can now come back as a re-proposal at `r + 1`
if validators locked on it.

### 3.5 Sequential finality (new)

A validator prevotes or precommits at `h + 1` only once `h` has a
`FinalityRecord`. Block production can still build ahead without waiting for
finality, but **depth is capped at 1**: no `h + 2` while `h` is uncertified,
so an unwind never discards more than one block. This rule alone makes the
D-25 state (certified descendants above an uncertified parent) impossible.

### 3.6 Safety, in one paragraph

If `B` finalizes at `(h, r)`, a quorum precommitted it, so at least `f + 1`
honest validators are locked on `B` at round `r`. In any later round an
honest validator locked on `B` prevotes something else only when it sees a
POL for another block at a round `≥ r`. That POL needs a quorum of prevotes
at that round, which includes at least one of those locked validators, and
that validator would only have prevoted another block with a POL from a
still later round. By induction no such POL exists, so no other block gets
a quorum of prevotes, and no honest validator precommits it. The paper has
the full proof; Informal Systems has a TLA+ model of it we can check our
restatement against.

### 3.7 D-25 under the new rules

A proposes `5627@0`, and B receives it. OVH doesn't receive it before its
propose timeout and prevotes nil.

- **A and B prevote the block, OVH prevotes nil (6,666 < quorum).** Nobody
  locks; all three precommit nil and time out; round 1 proposes a fresh
  block, and all three vote it. The dead-tip unwind drops `5627@0`.
- **All three prevote it, but OVH's precommit is late.** A and B locked on
  it at round 0; the round-1 proposer re-proposes it with the round-0 POL,
  and everyone precommits → final.

In both cases the height finalizes and the watermark follows.

## 4. What it costs

- **Latency.** One extra voting phase per height, so finality takes about
  one more gossip hop (~100–300 ms). Block time is unchanged because
  production doesn't wait for finality.
- **Wire and storage.** A new `PrevoteVote` gossip topic and tally,
  lock/valid state in `SignedVotes`, `pol_round` + POL certificate on
  `Block`. That means a schema bump and a devnet reset.
- **Accountability.** Prevote equivocation needs its own evidence variant and
  slash (`Fault::PrevoteEquivocation`), mirroring `PrecommitEquivocation`.
  Safety doesn't depend on slashing it, but accountability does. *Done in
  D-26: detected in `tally_prevote`, verified by `xc_artifact::verify`, and
  slashed like a double precommit.*
- **Code.** Mostly `arxd/finality` (event loop, tallies, timeouts),
  `core/executor::accept_block` (POL verification), the producer (propose
  the valid block), `arxd/network` (topic), `core/artifact` (new fault).

## 5. Alternative: adopt an existing engine

Malachite (Informal Systems, Rust, Apache-2.0) implements this algorithm
as a library: the application supplies values, validation and signing,
and Malachite runs the rounds. Starknet uses it.

- For: the hardest code to get right would be reviewed and model-checked
  code, not ours. Before mainnet, hand-rolled consensus is the biggest
  safety risk we carry.
- Against: we'd have to fit it to BLS aggregate certificates, `ep` in the
  precommit, our evidence/dispute pipeline and `SignedVotes`; and we'd take
  on a dependency on how Malachite evolves.

**Recommendation:** a time-boxed spike (≈1 week) wiring Malachite to the
two-validator devnet and running `late-block-harness.sh` against it, before
committing to either path. If integration costs more than the changes in
§3, implement §3 in-house and check it against the TLA+ model.

## 6. Mainnet requirements, whichever path

- **At least 4 roughly equal validators.** With 2 or 3, the quorum (6,667 of
  10,000) needs everyone, so any one slow node stops finality under *any*
  protocol, and the devnet can't exercise fault tolerance at all.
- **Harnesses that must pass:** `late-block-harness.sh` (this bug),
  `partition-heal-harness.sh`, `withholding-proposer-harness.sh`,
  `two-node-fault-harness.sh`.

## 7. Decisions needed

1. Malachite spike first, or go straight to §3 in-house?
2. Pipelining depth: cap at 1 as proposed (§3.5), or stop building ahead
   entirely (simpler, but block time then includes finality)?
3. Minimum validator count for mainnet genesis (proposed: 4).
