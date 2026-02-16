//! Integration tests for the btc_migrate binary.
//!
//! Tests the OP_RETURN payload generation by exercising the library
//! functions directly (since running the binary requires ML-DSA keygen
//! which is slow in debug mode).

use hashes::{Hash, sha256};
use pq_bitcoin_lib::op_return::{
    FLAG_DUAL_SIG, FLAG_GROTH16, FLAG_PLONK, LEVEL_ML_DSA_44, LEVEL_ML_DSA_65, LEVEL_ML_DSA_87,
    MAGIC, MigrationPayload, PAYLOAD_SIZE, VERSION,
};
use pq_bitcoin_lib::{ml_dsa_level_name, public_key_to_btc_address, validate_pq_pubkey};

// ============================================================
//  End-to-End Migration Flow
// ============================================================

/// Simulate the full migration flow as btc_migrate does:
/// 1. Generate keys
/// 2. Derive BTC address
/// 3. Build OP_RETURN payload
/// 4. Verify commitments
/// 5. Parse from script
#[test]
fn test_full_migration_flow_ml_dsa_65() {
    // 1. Simulated ECDSA compressed pubkey (33 bytes, starts with 0x02 or 0x03).
    let ecdsa_pubkey = {
        let mut k = vec![0x02u8]; // compressed prefix
        k.extend_from_slice(&[0xAB; 32]);
        k
    };

    // 2. Derive BTC address.
    let btc_address = public_key_to_btc_address(&ecdsa_pubkey);
    assert_eq!(btc_address.len(), 25); // 1 version + 20 hash + 4 checksum

    // 3. Simulated ML-DSA-65 public key.
    let pq_pubkey = vec![0xCC; 1952];
    assert!(validate_pq_pubkey(&pq_pubkey));
    assert_eq!(ml_dsa_level_name(&pq_pubkey), "ML-DSA-65");

    // 4. Build payload.
    let mock_proof = btc_address.clone();
    let payload = MigrationPayload::new(&pq_pubkey, &mock_proof, FLAG_GROTH16);

    // 5. Verify payload correctness.
    assert_eq!(payload.level, LEVEL_ML_DSA_65);
    assert!(payload.is_groth16());
    assert!(!payload.is_plonk());
    assert!(!payload.is_dual_sig());
    assert!(payload.verify_pq_commitment(&pq_pubkey));
    assert!(payload.verify_proof_commitment(&mock_proof));

    // 6. Encode to wire format.
    let encoded = payload.encode();
    assert_eq!(encoded.len(), PAYLOAD_SIZE);
    assert_eq!(&encoded[0..4], &MAGIC);
    assert_eq!(encoded[4], VERSION);

    // 7. Build OP_RETURN script.
    let script = payload.to_script();
    assert_eq!(script[0], 0x6a);
    assert!(MigrationPayload::is_migration_script(&script));

    // 8. Parse back from script.
    let parsed = MigrationPayload::from_script(&script).unwrap();
    assert_eq!(payload, parsed);
}

/// Same flow with ML-DSA-44.
#[test]
fn test_full_migration_flow_ml_dsa_44() {
    let ecdsa_pubkey = {
        let mut k = vec![0x03u8];
        k.extend_from_slice(&[0x11; 32]);
        k
    };
    let btc_address = public_key_to_btc_address(&ecdsa_pubkey);

    let pq_pubkey = vec![0xDD; 1312]; // ML-DSA-44
    assert!(validate_pq_pubkey(&pq_pubkey));
    assert_eq!(ml_dsa_level_name(&pq_pubkey), "ML-DSA-44");

    let payload = MigrationPayload::new(&pq_pubkey, &btc_address, FLAG_PLONK);
    assert_eq!(payload.level, LEVEL_ML_DSA_44);
    assert!(payload.is_plonk());

    let script = payload.to_script();
    let parsed = MigrationPayload::from_script(&script).unwrap();
    assert_eq!(payload, parsed);
}

/// Same flow with ML-DSA-87.
#[test]
fn test_full_migration_flow_ml_dsa_87() {
    let ecdsa_pubkey = {
        let mut k = vec![0x02u8];
        k.extend_from_slice(&[0x22; 32]);
        k
    };
    let btc_address = public_key_to_btc_address(&ecdsa_pubkey);

    let pq_pubkey = vec![0xEE; 2592]; // ML-DSA-87
    assert!(validate_pq_pubkey(&pq_pubkey));
    assert_eq!(ml_dsa_level_name(&pq_pubkey), "ML-DSA-87");

    let payload = MigrationPayload::new(&pq_pubkey, &btc_address, FLAG_DUAL_SIG);
    assert_eq!(payload.level, LEVEL_ML_DSA_87);
    assert!(payload.is_dual_sig());

    let script = payload.to_script();
    let parsed = MigrationPayload::from_script(&script).unwrap();
    assert_eq!(payload, parsed);
}

// ============================================================
//  Cross-Verification: Hash Commitment Integrity
// ============================================================

/// Verify that a PQ key commitment can be verified independently
/// using only the raw hash — as an indexer or third party would.
#[test]
fn test_independent_commitment_verification() {
    let pq_pubkey = vec![0xAA; 1952];
    let proof = b"stark-proof-bytes-here";

    let payload = MigrationPayload::new(&pq_pubkey, proof, FLAG_GROTH16);

    // Independently compute hashes.
    let expected_pq_hash = sha256::Hash::hash(&pq_pubkey);
    let expected_proof_hash = sha256::Hash::hash(proof);

    assert_eq!(payload.pq_pubkey_hash, *expected_pq_hash.as_byte_array());
    assert_eq!(payload.proof_hash, *expected_proof_hash.as_byte_array());
}

/// Verify that wrong key is rejected.
#[test]
fn test_wrong_key_commitment_rejected() {
    let pq_pubkey = vec![0xAA; 1952];
    let payload = MigrationPayload::new(&pq_pubkey, b"proof", FLAG_GROTH16);

    // Slightly different key
    let mut wrong_key = pq_pubkey.clone();
    wrong_key[0] = 0xBB;
    assert!(!payload.verify_pq_commitment(&wrong_key));
}

// ============================================================
//  Script Round-Trip with Different Flag Combinations
// ============================================================

#[test]
fn test_script_roundtrip_all_flag_combinations() {
    let pq_pubkey = vec![0xAA; 1952];
    let proof = b"proof-data";

    let flag_sets: Vec<u8> = vec![
        0x00,
        FLAG_GROTH16,
        FLAG_PLONK,
        FLAG_DUAL_SIG,
        FLAG_GROTH16 | FLAG_DUAL_SIG,
        FLAG_PLONK | FLAG_DUAL_SIG,
    ];

    for flags in flag_sets {
        let payload = MigrationPayload::new(&pq_pubkey, proof, flags);
        let script = payload.to_script();
        let parsed = MigrationPayload::from_script(&script).unwrap();
        assert_eq!(payload, parsed, "Failed for flags 0x{:02x}", flags);
    }
}

// ============================================================
//  Edge Cases
// ============================================================

/// Ensure invalid PQ key sizes are rejected by validate_pq_pubkey.
#[test]
fn test_invalid_pq_key_sizes() {
    assert!(!validate_pq_pubkey(&vec![0; 0]));
    assert!(!validate_pq_pubkey(&vec![0; 100]));
    assert!(!validate_pq_pubkey(&vec![0; 1311])); // too short for ML-DSA-44
    assert!(!validate_pq_pubkey(&vec![0; 1313])); // between levels
    assert!(!validate_pq_pubkey(&vec![0; 1951])); // too short for ML-DSA-65
    assert!(!validate_pq_pubkey(&vec![0; 1953])); // between levels
    assert!(!validate_pq_pubkey(&vec![0; 2591])); // too short for ML-DSA-87
    assert!(!validate_pq_pubkey(&vec![0; 2593])); // too long
    assert!(!validate_pq_pubkey(&vec![0; 10000]));
}

/// Verify that valid PQ key sizes are accepted.
#[test]
fn test_valid_pq_key_sizes() {
    assert!(validate_pq_pubkey(&vec![0; 1312])); // ML-DSA-44
    assert!(validate_pq_pubkey(&vec![0; 1952])); // ML-DSA-65
    assert!(validate_pq_pubkey(&vec![0; 2592])); // ML-DSA-87
}

/// Non-OP_RETURN scripts should not be detected.
#[test]
fn test_non_op_return_scripts_rejected() {
    // P2PKH script (starts with OP_DUP, not OP_RETURN)
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[0x00; 20]);
    assert!(!MigrationPayload::is_migration_script(&p2pkh));

    // Empty
    assert!(!MigrationPayload::is_migration_script(&[]));

    // OP_RETURN but wrong content
    let wrong = vec![0x6a, 0x04, 0x00, 0x01, 0x02, 0x03];
    assert!(!MigrationPayload::is_migration_script(&wrong));
}

/// BTC address derivation determinism.
#[test]
fn test_btc_address_deterministic() {
    let pubkey = {
        let mut k = vec![0x02u8];
        k.extend_from_slice(&[0xAA; 32]);
        k
    };
    let addr1 = public_key_to_btc_address(&pubkey);
    let addr2 = public_key_to_btc_address(&pubkey);
    assert_eq!(addr1, addr2);
    assert_eq!(addr1.len(), 25);
}

/// Two different keys produce different BTC addresses.
#[test]
fn test_different_keys_different_addresses() {
    let key1 = {
        let mut k = vec![0x02u8];
        k.extend_from_slice(&[0xAA; 32]);
        k
    };
    let key2 = {
        let mut k = vec![0x02u8];
        k.extend_from_slice(&[0xBB; 32]);
        k
    };
    let addr1 = public_key_to_btc_address(&key1);
    let addr2 = public_key_to_btc_address(&key2);
    assert_ne!(addr1, addr2);
}

// ============================================================
//  Payload Construction from Pre-Computed Hashes
// ============================================================

/// Simulate what an indexer would do: receive hashes and reconstruct.
#[test]
fn test_from_hashes_interop() {
    let pq_pubkey = vec![0xAA; 1952];
    let proof = b"proof-data";

    // Create via the normal path.
    let payload1 = MigrationPayload::new(&pq_pubkey, proof, FLAG_GROTH16);

    // Create via from_hashes (as an indexer would).
    let pq_hash = sha256::Hash::hash(&pq_pubkey);
    let proof_hash = sha256::Hash::hash(proof);
    let payload2 = MigrationPayload::from_hashes(
        *pq_hash.as_byte_array(),
        *proof_hash.as_byte_array(),
        FLAG_GROTH16,
        LEVEL_ML_DSA_65,
    );

    assert_eq!(payload1, payload2);
    assert_eq!(payload1.encode(), payload2.encode());
}
