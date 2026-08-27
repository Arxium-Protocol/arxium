#!/usr/bin/env bash
# Backs up the node's base_path (validator.key, network.key, config, and every
# chain's RocksDB data — e.g. corechain/) to a dated tarball. validator.key is
# the validator's entire signing identity with no recovery path if lost — this
# exists so losing the VPS disk doesn't mean losing the validator forever.
#
# Usage: ./scripts/backup-node.sh <base-path> <backup-dir> [keep-count]
#   e.g. ./scripts/backup-node.sh ~/.arxium /var/backups/arxium 14
#
# Run from cron (daily is plenty — validator.key never changes after first
# generation, and RocksDB snapshots are cheap to take more often than they
# need to be restored). Copy the resulting tarballs off-box (rsync/rclone/
# whatever the VPS provider offers) — a backup that lives on the same disk
# as what it's backing up doesn't survive the disk failing.
set -euo pipefail

base_path="${1:?usage: backup-node.sh <base-path> <backup-dir> [keep-count]}"
backup_dir="${2:?usage: backup-node.sh <base-path> <backup-dir> [keep-count]}"
keep="${3:-14}"

[ -f "$base_path/validator.key" ] || { echo "no validator.key found in $base_path — wrong --base-path?" >&2; exit 1; }

mkdir -p "$backup_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$backup_dir/arxium-backup-$stamp.tar.gz"

tar -czf "$out" -C "$base_path" .
echo "backed up $base_path -> $out"

# prune old backups beyond $keep, oldest first
ls -1t "$backup_dir"/arxium-backup-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm --
