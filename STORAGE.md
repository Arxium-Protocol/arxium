# Node storage: retention policy

**The node is a permanent archive. RocksDB growth is unbounded and intended — there is no pruning job.**

Why: NodeIndexer (see `NodeIndexer/`) is the durable, queryable historical-data
layer — ArxPlusApi's balance/history reads go through NodeIndexer's gRPC
service, not the node's own RPC (`core/rpc`'s `get_actions_by_address` route
was removed; see `core/README.md`). The node's RocksDB only needs to answer
"what's the current/recent chain state," which the column-family split
(`core/storage`'s `meta`/`blocks`/`accounts`/`validators` CFs) already keeps
cheap to query. Since nothing latency-sensitive depends on the node itself
holding old block bodies, pruning would only be justified by disk-size
pressure — not a problem yet at devnet/testnet scale.

If disk growth ever becomes the trigger: prune block bodies older than
`H - N` once NodeIndexer confirms ingestion past that height, keeping
`account`/`validators` CF entries (current state) untouched. Not built until
that trigger is actually hit — see `implementation_plan.md` Phase 5.
