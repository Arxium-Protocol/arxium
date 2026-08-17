#!/usr/bin/env bash
# Backs up the node's data directory (validator.key, network.key, RocksDB)
# to a dated tarball. validator.key is the validator's entire signing
# identity with no recovery path if lost — this exists so losing the VPS
# disk doesn't mean losing the validator forever.
#
# Usage: ./scripts/backup-node.sh <data-dir> <backup-dir> [keep-count]
#   e.g. ./scripts/backup-node.sh /var/lib/arxium/data /var/backups/arxium 14
#
# Run from cron (daily is plenty — validator.key never changes after first
# generation, and RocksDB snapshots are cheap to take more often than they
# need to be restored). Copy the resulting tarballs off-box (rsync/rclone/
# whatever the VPS provider offers) — a backup that lives on the same disk
# as what it's backing up doesn't survive the disk failing.
set -euo pipefail

data_dir="${1:?usage: backup-node.sh <data-dir> <backup-dir> [keep-count]}"
backup_dir="${2:?usage: backup-node.sh <data-dir> <backup-dir> [keep-count]}"
keep="${3:-14}"

[ -f "$data_dir/validator.key" ] || { echo "no validator.key found in $data_dir — wrong --base-path?" >&2; exit 1; }

mkdir -p "$backup_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$backup_dir/arxium-backup-$stamp.tar.gz"

tar -czf "$out" -C "$data_dir" .
echo "backed up $data_dir -> $out"

# prune old backups beyond $keep, oldest first
ls -1t "$backup_dir"/arxium-backup-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm --
