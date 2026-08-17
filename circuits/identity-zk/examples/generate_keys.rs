//! One-time devnet key generation: writes `pk.bin`/`vk.bin` next to this
//! crate's `Cargo.toml`, checked into the repo. **Not a real trusted-setup
//! ceremony** — see the module docs in `src/lib.rs`. Re-run only if the
//! circuit itself changes; anyone can re-derive new keys, they just won't
//! match proofs generated against the checked-in ones.

use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use circuit_identity_zk::setup;

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, vk) = setup(&mut rng);

    let dir = concat!(env!("CARGO_MANIFEST_DIR"));
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).expect("serialize proving key");
    std::fs::write(format!("{dir}/pk.bin"), pk_bytes).expect("write pk.bin");

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).expect("serialize verifying key");
    std::fs::write(format!("{dir}/vk.bin"), vk_bytes).expect("write vk.bin");

    println!("wrote devnet pk.bin/vk.bin to {dir}");
}
