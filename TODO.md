A few real gaps I noticed while reading through the event loop, ranked by how much they matter:

~~Reconnect wipes the penalty counters.~~ **Fixed.** `bad_gossip` no longer clears on `ConnectionEstablished` (only `sync_failures`, which tracks honest transient failures, still does). Once a peer crosses `MAX_BAD_GOSSIP` it's now handed to `allow_block_list::Behaviour<BlockedPeers>` (`transport.rs`), which refuses the peer at the swarm level — a redial doesn't get a fresh connection to spam on. Regression test: `gossip::tests::crossing_threshold_bans_peer_permanently`.

~~No message size ceiling is set explicitly.~~ **Fixed.** gossipsub's real default is 65536 bytes — close enough to this chain's worst case (100 actions/block, larger action variants carrying a ZK proof or BLS pubkey put a full block in the tens-of-KB range) to be a real risk. `max_transmit_size` now set explicitly to 1 MiB in `transport.rs`, in line with other chains' gossip caps (Cosmos ~4 MiB, Ethereum consensus 10 MiB).

~~Observability is just a peer-count gauge.~~ **Fixed.** Extended the existing `metrics`/Prometheus setup (`GET /metrics`) rather than pulling in a second stack — added `arxium_gossip_accepted_total{topic}` / `arxium_gossip_rejected_total{topic,reason}` (topic: actions/blocks/precommits/sync, reason: bad/stale) emitted from the same sites `record_bad_gossip` already covers plus the accept paths, `arxium_gossip_peers_banned_total` on ban, and `arxium_sync_requests_total{kind}` / `arxium_sync_responses_total{kind}` / `arxium_sync_outbound_failures_total` / `arxium_sync_inbound_failures_total` around the sync request/response cycle (`sync.rs`, `lib.rs`). Skipped a round-trip-*latency* histogram — would need correlating request IDs to send timestamps per in-flight request, real added complexity for something nothing has asked for yet; add it if the count-only counters turn out not to be enough signal.

Smaller/lower-priority: no AutoNAT/DCUtR for nodes behind NAT (fine for devnet, matters once nodes aren't all reachable directly), and the mdns-double-dial ponytail note is already flagged as harmless.

---
