// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Slashing protection for this validator's own finality votes — the vote
//! counterpart of `arxd/node`'s `SignedHeight`.
//!
//! What this validator already signed used to live only in the chain DB. A DB
//! restored from a backup or checkpoint, moved to a new machine, or rolled
//! back by a crash forgets it, and the node could then precommit a different
//! block at a (height, round) it already voted on (`PrecommitEquivocation`),
//! or break S2 (`docs/consensus-safety.md` §2) by voting timeout on a round
//! it precommitted in, or the reverse. Every one of those is a full slash and
//! a tombstone.
//!
//! This file lives beside the keys, outside `<chain>/data`, so wiping or
//! restoring the DB doesn't touch it. Each vote is recorded (fsynced) before
//! it is signed; a crash in between only costs that vote.

use std::path::{Path, PathBuf};

const SIGNED_VOTES_FILE: &str = "signed_votes";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Precommit,
    Timeout,
}

#[derive(Clone, Debug)]
struct Entry {
    kind: Kind,
    height: u64,
    round: u32,
    /// Block hash for a precommit, parent hash for a timeout — what the
    /// signature binds besides height/round.
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
    /// `p|t <height> <round> <hash>` line per signed vote.
    pub fn load(base_path: &Path, genesis_hex: &str) -> Result<Self, String> {
        let path = base_path.join(SIGNED_VOTES_FILE);
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

    /// Records a precommit for `hash` at `(height, round)` before it is
    /// signed. `Err` means signing it would be a slashable fault (or the
    /// record couldn't be made durable) — don't sign.
    pub fn claim_precommit(&mut self, height: u64, round: u32, hash: &str) -> Result<(), String> {
        self.claim(Kind::Precommit, height, round, hash)
    }

    /// Records a round-timeout vote (against `parent_hash`) before it is
    /// signed. Same contract as `claim_precommit`.
    pub fn claim_timeout(
        &mut self,
        height: u64,
        round: u32,
        parent_hash: &str,
    ) -> Result<(), String> {
        self.claim(Kind::Timeout, height, round, parent_hash)
    }

    fn claim(&mut self, kind: Kind, height: u64, round: u32, hash: &str) -> Result<(), String> {
        if height <= self.floor {
            return Err(format!(
                "height {height} is at or below the pruned floor {}",
                self.floor
            ));
        }
        // At most one entry per (height, round): a second one is always refused.
        if let Some(e) = self
            .entries
            .iter()
            .find(|e| e.height == height && e.round == round)
        {
            if e.kind != kind {
                // S2: precommit and timeout in the same round, either order.
                return Err(format!(
                    "already signed a {:?} vote at height {height} round {round}",
                    e.kind
                ));
            }
            if e.hash != hash {
                return Err(format!(
                    "already signed a {kind:?} vote for {} at height {height} round {round}",
                    e.hash
                ));
            }
            return Ok(()); // the identical vote again: same message, no fault
        }
        self.entries.push(Entry {
            kind,
            height,
            round,
            hash: hash.to_string(),
        });
        self.persist()
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

    /// Temp file, fsync, rename — the whole file each time.
    ///
    /// ponytail: rewrites every entry per vote; that's ≤ a few hundred short
    /// lines (retention window × rounds). Append + periodic compaction if it
    /// ever shows up in a profile.
    fn persist(&self) -> Result<(), String> {
        use std::io::Write;
        let mut text = format!("{} {}\n", self.genesis, self.floor);
        for e in &self.entries {
            let kind = match e.kind {
                Kind::Precommit => "p",
                Kind::Timeout => "t",
            };
            text.push_str(&format!("{kind} {} {} {}\n", e.height, e.round, e.hash));
        }
        let tmp = self.path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| format!("failed to write {}: {e}", self.path.display()))
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
            votes.claim_timeout(10, 0, "P").is_err(),
            "S2: precommit then timeout"
        );
        assert!(
            votes.claim_precommit(11, 0, "C").is_err(),
            "S2: timeout then precommit"
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
}
