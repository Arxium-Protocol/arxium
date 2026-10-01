// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Slashing protection for this validator's own finality votes — the vote
//! counterpart of `arxd/node`'s `SignedHeight`.
//!
//! What this validator already signed used to live only in the chain DB. A DB
//! restored from a backup or checkpoint, moved to a new machine, or rolled
//! back by a crash forgets it, and the node could then sign a second,
//! different prevote or precommit at a (height, round) it already voted on
//! (`PrecommitEquivocation`: a full slash and a tombstone), vote in a round it
//! already left, or forget its lock and prevote against it
//! (`docs/consensus-safety.md` §2, V1–V3). The lock is not stored separately:
//! it *is* the latest precommit recorded here.
//!
//! This file lives in `<base_path>/<chain>/`, outside `data/`, so wiping or
//! restoring the DB doesn't touch it (the node picks the directory; see
//! `slashing_protection_dir` in `arxd/node`). Each vote is recorded (fsynced) before
//! it is signed; a crash in between only costs that vote.

use std::path::{Path, PathBuf};

const SIGNED_VOTES_FILE: &str = "signed_votes";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Prevote,
    Precommit,
    Timeout,
}

#[derive(Clone, Debug)]
struct Entry {
    kind: Kind,
    height: u64,
    round: u32,
    /// Block hash for a prevote or precommit, parent hash for a timeout —
    /// what the signature binds besides height/round.
    hash: String,
}

/// Every vote this validator signed at heights above `floor`, tagged with the
/// genesis hash so a genesis reset starts clean instead of refusing forever.
/// Votes at or below `floor` are refused outright: entries there were pruned,
/// so whatever was signed there can no longer be checked.
pub struct SignedVotes {
    path: PathBuf,
    genesis: String,
    floor: u64,
    entries: Vec<Entry>,
}

impl SignedVotes {
    /// File format: first line `<genesis> <floor>`, then one
    /// `v|p|t <height> <round> <hash>` line per signed vote (prevote,
    /// precommit, timeout).
    pub fn load(dir: &Path, genesis_hex: &str) -> Result<Self, String> {
        let path = dir.join(SIGNED_VOTES_FILE);
        let mut votes = Self {
            path,
            genesis: genesis_hex.to_string(),
            floor: 0,
            entries: Vec::new(),
        };
        let text = match std::fs::read_to_string(&votes.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(votes),
            Err(e) => return Err(format!("failed to read {}: {e}", votes.path.display())),
        };
        let malformed = || {
            format!(
                "{} is malformed — restore it rather than deleting it, or this validator may \
                 sign conflicting finality votes",
                votes.path.display()
            )
        };
        let mut lines = text.lines();
        let header: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
        let [genesis, floor] = header[..] else {
            return Err(malformed());
        };
        if genesis != genesis_hex {
            return Ok(votes); // different chain: nothing here applies
        }
        votes.floor = floor.parse().map_err(|_| malformed())?;
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let [kind, height, round, hash] = parts[..] else {
                return Err(malformed());
            };
            votes.entries.push(Entry {
                kind: match kind {
                    "v" => Kind::Prevote,
                    "p" => Kind::Precommit,
                    "t" => Kind::Timeout,
                    _ => return Err(malformed()),
                },
                height: height.parse().map_err(|_| malformed())?,
                round: round.parse().map_err(|_| malformed())?,
                hash: hash.to_string(),
            });
        }
        Ok(votes)
    }

    /// An empty record in a fresh temp dir, for tests that spawn finality.
    #[cfg(test)]
    pub(crate) fn scratch() -> Self {
        Self::load(&tests::dir(), "test").unwrap()
    }

    /// Votes at or below this height are always refused.
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// This validator's lock at `height`: its latest precommit there, as
    /// `(round, block_hash)`.
    pub fn lock(&self, height: u64) -> Option<(u32, &str)> {
        self.entries
            .iter()
            .filter(|e| e.height == height && e.kind == Kind::Precommit)
            .max_by_key(|e| e.round)
            .map(|e| (e.round, e.hash.as_str()))
    }

    /// Records a prevote for `hash` at `(height, round)` before it is signed.
    /// `pol_round` is the round of the quorum of prevotes (a `PolRecord`) the
    /// caller holds for `hash`, if any: it is what lets a locked validator
    /// prevote a block other than the one it is locked on (V3). `Err` means
    /// signing would break a rule (or the record couldn't be made durable) —
    /// don't sign.
    pub fn claim_prevote(
        &mut self,
        height: u64,
        round: u32,
        hash: &str,
        pol_round: Option<u32>,
    ) -> Result<(), String> {
        if let Some((locked_round, locked)) = self.lock(height)
            && locked != hash
            && !pol_round.is_some_and(|pol| locked_round <= pol && pol <= round)
        {
            metrics::counter!("arxium_finality_votes_refused_total", "reason" => "lock")
                .increment(1);
            return Err(format!(
                "locked on {locked} since round {locked_round} at height {height}, and no \
                 quorum of prevotes for {hash} at or after that round"
            ));
        }
        self.claim(Kind::Prevote, height, round, hash)
    }

    /// Records a precommit for `hash` at `(height, round)` before it is
    /// signed — which also makes it this validator's lock. The caller must
    /// hold a quorum of prevotes for `hash` at this round (V4). Same contract
    /// as `claim_prevote`.
    pub fn claim_precommit(&mut self, height: u64, round: u32, hash: &str) -> Result<(), String> {
        self.claim(Kind::Precommit, height, round, hash)
    }

    /// Records a round-timeout vote (against `parent_hash`) before it is
    /// signed. Allowed after prevoting or precommitting in the same round —
    /// safety rests on the lock now, not on S2 — but it ends this
    /// validator's voting in that round. Same contract as `claim_prevote`.
    pub fn claim_timeout(
        &mut self,
        height: u64,
        round: u32,
        parent_hash: &str,
    ) -> Result<(), String> {
        self.claim(Kind::Timeout, height, round, parent_hash)
    }

    /// Every refusal is counted in `arxium_finality_votes_refused_total{reason}`:
    /// `floor` is routine catch-up, `round_left` is the V2 guard after a normal
    /// round change (D-25), `conflict` means the file just saved this
    /// validator from a slash (a restore or rollback happened), and
    /// `write_failed` means the vote was skipped because the record couldn't
    /// be made durable (disk full, permissions).
    fn claim(&mut self, kind: Kind, height: u64, round: u32, hash: &str) -> Result<(), String> {
        let refused = |reason: &'static str| {
            metrics::counter!("arxium_finality_votes_refused_total", "reason" => reason)
                .increment(1);
        };
        if height <= self.floor {
            refused("floor");
            return Err(format!(
                "height {height} is at or below the pruned floor {}",
                self.floor
            ));
        }
        // At most one entry per (height, round, kind): a second, different
        // one is equivocation (V1).
        if let Some(e) = self
            .entries
            .iter()
            .find(|e| e.height == height && e.round == round && e.kind == kind)
        {
            if e.hash != hash {
                refused("conflict");
                return Err(format!(
                    "already signed a {kind:?} vote for {} at height {height} round {round}",
                    e.hash
                ));
            }
            return Ok(()); // the identical vote again: same message, no fault
        }
        // V2: a round this validator left — timed out, or voted past — gets
        // no more prevotes or precommits. Locking in round `r` after acting
        // in `r + 1` is what would let two blocks finalize.
        if kind != Kind::Timeout
            && let Some(e) = self.entries.iter().find(|e| {
                e.height == height
                    && (e.round > round || (e.round == round && e.kind == Kind::Timeout))
            })
        {
            refused("round_left");
            return Err(format!(
                "already left round {round} at height {height} ({:?} vote at round {})",
                e.kind, e.round
            ));
        }
        self.entries.push(Entry {
            kind,
            height,
            round,
            hash: hash.to_string(),
        });
        self.persist().inspect_err(|_| {
            // Not durable, so not claimed: otherwise a retry of the same vote
            // would hit the "identical vote again" branch and get signed with
            // no record on disk.
            self.entries.pop();
            refused("write_failed");
        })
    }

    /// Drops entries below `cutoff` and raises the floor to match, so a DB
    /// restored far enough back can never vote there again unchecked.
    pub fn prune_below(&mut self, cutoff: u64) -> Result<(), String> {
        let floor = cutoff.saturating_sub(1);
        if floor <= self.floor {
            return Ok(());
        }
        self.floor = floor;
        self.entries.retain(|e| e.height > floor);
        self.persist()
    }

    /// Temp file, fsync, rename, fsync dir — the whole file each time.
    ///
    /// ponytail: rewrites every entry per vote; that's ≤ a few hundred short
    /// lines (retention window × rounds). Append + periodic compaction if it
    /// ever shows up in a profile.
    fn persist(&self) -> Result<(), String> {
        let mut text = format!("{} {}\n", self.genesis, self.floor);
        for e in &self.entries {
            let kind = match e.kind {
                Kind::Prevote => "v",
                Kind::Precommit => "p",
                Kind::Timeout => "t",
            };
            text.push_str(&format!("{kind} {} {} {}\n", e.height, e.round, e.hash));
        }
        xc_primitives::keyfile::replace_file_durably(&self.path, text.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-signed-votes-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_restarted_validator_refuses_conflicting_votes() {
        let dir = dir();
        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        votes.claim_precommit(10, 0, "A").unwrap();
        votes.claim_timeout(11, 0, "A").unwrap();

        // Restart: a fresh load from the same file, as after a DB restore.
        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        assert!(votes.claim_precommit(10, 0, "A").is_ok(), "same vote again");
        assert!(votes.claim_precommit(10, 0, "B").is_err(), "equivocation");
        assert!(
            votes.claim_timeout(10, 0, "P").is_ok(),
            "D-25: a precommitter may still time the round out"
        );
        assert!(
            votes.claim_precommit(11, 0, "C").is_err(),
            "V2: no precommit in a round already timed out"
        );
        assert!(
            votes.claim_timeout(11, 0, "Z").is_err(),
            "timeout on another parent"
        );
        assert!(
            votes.claim_precommit(10, 1, "B").is_ok(),
            "a new round is fine"
        );

        // Pruned heights are refused, not forgotten.
        votes.prune_below(11).unwrap();
        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        assert!(votes.claim_precommit(10, 5, "D").is_err());
        assert!(
            votes.claim_timeout(11, 0, "Z").is_err(),
            "kept above the floor"
        );

        // A genesis reset starts over; a corrupt file stops boot.
        assert!(
            SignedVotes::load(&dir, "g2")
                .unwrap()
                .claim_precommit(1, 0, "X")
                .is_ok()
        );
        std::fs::write(dir.join(SIGNED_VOTES_FILE), "garbage").unwrap();
        assert!(SignedVotes::load(&dir, "g1").is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// V3 and V2 across a restart: the lock is the latest precommit, it
    /// survives a reload, only a quorum of prevotes at or after its round
    /// releases it, and a round left behind gets no more votes.
    #[test]
    fn the_lock_survives_a_restart_and_only_a_later_quorum_releases_it() {
        let dir = dir();
        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        votes.claim_prevote(7, 1, "A", None).unwrap();
        votes.claim_precommit(7, 1, "A").unwrap();

        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        assert_eq!(votes.lock(7), Some((1, "A")));
        assert!(
            votes.claim_prevote(7, 2, "A", None).is_ok(),
            "the locked block"
        );
        assert!(
            votes.claim_prevote(7, 3, "B", None).is_err(),
            "another block with no quorum behind it"
        );
        assert!(
            votes.claim_prevote(7, 3, "B", Some(0)).is_err(),
            "a quorum older than the lock doesn't release it"
        );
        assert!(votes.claim_prevote(7, 3, "B", Some(2)).is_ok());
        assert!(
            votes.claim_prevote(7, 3, "C", Some(2)).is_err(),
            "equivocation"
        );
        assert!(
            votes.claim_precommit(7, 2, "B").is_err(),
            "V2: round 2 is behind a round-3 prevote"
        );
        votes.claim_timeout(7, 3, "P").unwrap();
        assert!(
            votes.claim_precommit(7, 3, "B").is_err(),
            "V2: round 3 was timed out"
        );
        votes.claim_precommit(7, 4, "B").unwrap();
        assert_eq!(votes.lock(7), Some((4, "B")), "the lock moves forward");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A vote whose record couldn't be written is not claimed: retrying it
    /// must try the write again, not sign on the in-memory entry alone.
    #[test]
    fn a_failed_write_does_not_leave_the_vote_claimed() {
        let dir = dir().join("missing");
        let mut votes = SignedVotes::load(&dir, "g1").unwrap();
        assert!(
            votes.claim_precommit(10, 0, "A").is_err(),
            "no dir to write to"
        );
        assert!(
            votes.claim_precommit(10, 0, "A").is_err(),
            "retry still refused"
        );

        std::fs::create_dir_all(&dir).unwrap();
        votes.claim_precommit(10, 0, "A").unwrap();
        let mut reloaded = SignedVotes::load(&dir, "g1").unwrap();
        assert!(
            reloaded.claim_precommit(10, 0, "B").is_err(),
            "record is on disk"
        );
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }
}
