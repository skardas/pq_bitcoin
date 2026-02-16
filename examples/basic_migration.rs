//! Example: Basic Bitcoin P2PKH → PQ Migration
//!
//! Demonstrates how to derive a BTC address, generate an OP_RETURN migration
//! payload, and build the full Bitcoin script.

use pq_bitcoin_lib::op_return::{MigrationPayload, FLAG_GROTH16};
use pq_bitcoin_lib::{ml_dsa_level_name, public_key_to_btc_address, validate_pq_pubkey};

fn main() {
    // ── 1. Derive BTC address from compressed ECDSA public key ──
    let pubkey =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("Invalid hex");
    let btc_address = public_key_to_btc_address(&pubkey).expect("Address derivation failed");
    println!("BTC Address:    0x{}", hex::encode(&btc_address));

    // ── 2. Simulate a PQ public key (ML-DSA-65 = 1952 bytes) ────
    let pq_pubkey = vec![0xAA; 1952];
    assert!(validate_pq_pubkey(&pq_pubkey));
    println!("PQ Key Level:   {}", ml_dsa_level_name(&pq_pubkey));

    // ── 3. Build OP_RETURN migration payload ────────────────────
    let proof_bytes = vec![0xBB; 256]; // placeholder proof
    let payload = MigrationPayload::new(&pq_pubkey, &proof_bytes, FLAG_GROTH16);

    println!("PQ Key Hash:    0x{}", hex::encode(payload.pq_pubkey_hash));
    println!("Proof Hash:     0x{}", hex::encode(payload.proof_hash));
    println!("Level:          {}", payload.level_name());
    println!("Groth16:        {}", payload.is_groth16());

    // ── 4. Generate full OP_RETURN script ────────────────────────
    let script = payload.to_script();
    println!("Script (hex):   0x{}", hex::encode(&script));
    println!("Script size:    {} bytes", script.len());

    // ── 5. Verify round-trip ────────────────────────────────────
    let decoded = MigrationPayload::from_script(&script).expect("Script round-trip failed");
    assert_eq!(decoded, payload);
    println!("\n✅ Round-trip verification passed!");
}
