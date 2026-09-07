# Fuzz targets

Four targets over every place the node decodes bytes it did not produce:

| target | what it covers |
| --- | --- |
| `block_decode` | a gossiped `Block<ActionPayload>`, decoded before any signature check |
| `raw_block_decode` | `RawBlock`/`RawAction`, the payload-agnostic decode an indexer runs — asserts its hash matches `Block::hash` for the same bytes |
| `sync_wire_decode` | `SyncRequest` and `SyncResponse` from whichever peer answered |
| `artifact_decode` | evidence artifact JSON plus `xc_artifact::verify` — attacker-authored by construction, since it names who gets slashed |

All four go through `xc_primitives::decode_wire_canonical`, which is what
`arxd/network`'s `decode_wire` calls, so what is fuzzed is the real path.

```sh
cargo install cargo-fuzz            # once
cargo +nightly fuzz build           # all targets
cargo +nightly fuzz run block_decode -- -max_total_time=300
cargo +nightly fuzz run block_decode fuzz/artifacts/block_decode/crash-...  # reproduce
```

A finding is a panic, an abort, an OOM, or a failed assertion. A decode
returning `Err` is the expected outcome for nearly every input.

## Corpus

`fuzz/corpus/` is gitignored. It is 12MB of random blobs across ~3000 files
after `cargo fuzz cmin`, and each target re-reaches its coverage from an empty
corpus in about a minute (~5M execs/min on an M-series laptop), so carrying it
in the repository costs more than it saves. Crash inputs under
`fuzz/artifacts/` are small and *are* committed — those are the regression
cases.

Findings that turn into a permanent check belong in the normal test suite, not
only here: the non-canonical-varint finding from the first run is
`core/primitives`'s `a_non_canonical_varint_is_rejected`.
