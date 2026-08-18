A few real gaps I noticed while reading through the event loop, ranked by how much they matter:

Reconnect wipes the penalty counters. ConnectionEstablished clears both bad_gossip and sync_failures for a peer (lib.rs). A malicious peer that's about to hit MAX_BAD_GOSSIP can just drop and redial to reset its score to zero and keep spamming forever — the ban is per-connection, not per-PeerId. Worth tracking bad-gossip counts in a small TTL'd map that survives reconnects (or applying gossipsub's own peer-scoring instead of hand-rolled counters).

No message size ceiling is set explicitly. gossipsub::Config::default() caps messages around 64KB. If a block ever grows past that it gets silently dropped from gossip (sync would eventually catch it up, but blocks would look like they "never arrive" over the fast path). Worth checking your max block size against the default and setting max_transmit_size explicitly if it's close.

Observability is just a peer-count gauge. No counters for gossip accept/reject rates, sync round-trips, or bad-gossip disconnects — so if something like #1 gets exploited in practice, you won't see it in metrics, only in logs.

Smaller/lower-priority: no AutoNAT/DCUtR for nodes behind NAT (fine for devnet, matters once nodes aren't all reachable directly), and the mdns-double-dial ponytail note is already flagged as harmless.

---
