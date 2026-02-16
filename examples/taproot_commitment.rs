//! Example: Taproot PQ Key Commitment
//!
//! Demonstrates building a Taproot script tree that commits to a PQ public key
//! and includes a timelock fallback for recovery.

use pq_bitcoin_lib::taproot::{PQMigrationTree, tap_tweak_hash};
use pq_bitcoin_lib::{ml_dsa_level_name, validate_pq_pubkey};

fn main() {
    // ── 1. Set up keys ──────────────────────────────────────────
    // In production, this would be a real x-only internal key (32 bytes)
    let internal_key: [u8; 32] = [0x02; 32]; // placeholder

    // ML-DSA-65 public key (1952 bytes)
    let pq_pubkey = vec![0xAA; 1952];
    assert!(validate_pq_pubkey(&pq_pubkey));
    println!("PQ Key Level:       {}", ml_dsa_level_name(&pq_pubkey));

    // ── 2. Build PQ Migration Tree ──────────────────────────────
    let timelock_blocks: u16 = 144; // ~1 day
    let tree = PQMigrationTree::new(&pq_pubkey, timelock_blocks);

    println!("PQ Pubkey Hash:     0x{}", hex::encode(tree.pq_pubkey_hash));
    println!("PQ Leaf Hash:       0x{}", hex::encode(tree.pq_leaf_hash));
    println!(
        "Timelock Leaf Hash: 0x{}",
        hex::encode(tree.timelock_leaf_hash)
    );
    println!("Merkle Root:        0x{}", hex::encode(tree.merkle_root));
    println!("Timelock:           {} blocks", tree.timelock_blocks);

    // ── 3. Compute Tweak Hash ───────────────────────────────────
    let tweak = tap_tweak_hash(&internal_key, Some(&tree.merkle_root));
    println!("Tweak Hash:         0x{}", hex::encode(tweak));

    // Also available via tree method:
    assert_eq!(tweak, tree.tweak_hash(&internal_key));

    // ── 4. Control Blocks ───────────────────────────────────────
    let pq_cb = tree.pq_leaf_control_block(&internal_key, 0);
    let tl_cb = tree.timelock_leaf_control_block(&internal_key, 0);
    println!("\nPQ Control Block:   0x{}", hex::encode(&pq_cb));
    println!("TL Control Block:   0x{}", hex::encode(&tl_cb));

    // ── 5. Verify Commitment ────────────────────────────────────
    assert!(tree.verify_pq_commitment(&pq_pubkey));
    assert!(!tree.verify_pq_commitment(&vec![0xBB; 1952])); // wrong key fails

    println!("\n✅ Taproot PQ commitment verified!");
}
