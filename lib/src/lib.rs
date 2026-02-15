use alloy_sol_types::sol;
use sha3::{Digest, Keccak256};

use hashes::{ripemd160, sha256, Hash};
use secp256k1::Message;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes btc_address;     // fixed-length address
        bytes pq_pubkey;       // fixed-length pq public key
    }
}

// ============================================================
//  ML-DSA (CRYSTALS-Dilithium) Constants — FIPS-204
// ============================================================

/// ML-DSA-65 public key size (1952 bytes).
pub const ML_DSA_65_PK_SIZE: usize = 1952;

/// ML-DSA-65 signature size (3309 bytes).
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

/// Minimum accepted PQ public key length for validation.
/// We accept ML-DSA-44 (1312), ML-DSA-65 (1952), or ML-DSA-87 (2592).
pub const ML_DSA_MIN_PK_SIZE: usize = 1312;

/// Maximum accepted PQ public key length.
pub const ML_DSA_MAX_PK_SIZE: usize = 2592;

// ============================================================
//  Bitcoin Address Derivation (P2PKH)
// ============================================================

pub fn public_key_to_btc_address(pubkey: &[u8]) -> Vec<u8> {
    assert_eq!(pubkey.len(), 33, "Public key should be 33 bytes (compressed)");
    // Step 1: SHA-256 hash
    let msg = sha256::Hash::hash(pubkey);
    let msg = Message::from_digest_slice(msg.as_ref()).unwrap();

    // Step 2: RIPEMD-160 hash
    let ripemd160_hash = ripemd160::Hash::hash(msg.as_ref());
    let msg :  &[u8] = ripemd160_hash.as_ref();

    // Step 3: Add version byte (0x00 for mainnet)
    let mut versioned_payload = vec![0x00];
    versioned_payload.extend(msg);

    // Step 4: Checksum calculation (double SHA-256)
    let msg = sha256::Hash::hash(versioned_payload.as_slice());
    let msg = Message::from_digest_slice(msg.as_ref()).unwrap();
    let msg = sha256::Hash::hash(msg.as_ref());
    let checksum_full = Message::from_digest_slice(msg.as_ref()).unwrap();
    let checksum = &checksum_full[0..4];

    // Step 5: Append checksum
    versioned_payload.extend(checksum);
    versioned_payload
}

// ============================================================
//  Ethereum Address Derivation (Keccak-256)
// ============================================================

pub fn public_key_to_eth_address(pubkey: &[u8]) -> Vec<u8> {
    assert_eq!(pubkey.len(), 64, "Public key should be 64 bytes (uncompressed, without 0x04 prefix)");
    let mut hasher = Keccak256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();

    // Ethereum address = last 20 bytes of Keccak-256 hash
    hash[12..].to_vec()
}

// ============================================================
//  Post-Quantum Key Validation
// ============================================================

/// Validates that a PQ public key has a valid ML-DSA size.
/// Accepts ML-DSA-44 (1312 bytes), ML-DSA-65 (1952 bytes), or ML-DSA-87 (2592 bytes).
pub fn validate_pq_pubkey(pq_pubkey: &[u8]) -> bool {
    matches!(pq_pubkey.len(), 1312 | 1952 | 2592)
}

/// Returns the ML-DSA security level name based on public key length.
pub fn ml_dsa_level_name(pq_pubkey: &[u8]) -> &'static str {
    match pq_pubkey.len() {
        1312 => "ML-DSA-44",
        1952 => "ML-DSA-65",
        2592 => "ML-DSA-87",
        _ => "Unknown",
    }
}

// ============================================================
//  Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolType;

    // ----------------------------------------------------------
    //  BTC address derivation tests
    // ----------------------------------------------------------

    #[test]
    fn test_btc_address_from_compressed_pubkey() {
        // Known compressed public key (33 bytes, starts with 0x02 or 0x03)
        let pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();
        assert_eq!(pubkey.len(), 33);

        let address = public_key_to_btc_address(&pubkey);
        // P2PKH address = 25 bytes (1 version + 20 hash + 4 checksum)
        assert_eq!(address.len(), 25);
        // Version byte should be 0x00 (mainnet)
        assert_eq!(address[0], 0x00);
    }

    #[test]
    fn test_btc_address_deterministic() {
        let pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();

        let addr1 = public_key_to_btc_address(&pubkey);
        let addr2 = public_key_to_btc_address(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[test]
    #[should_panic(expected = "Public key should be 33 bytes")]
    fn test_btc_address_invalid_pubkey_length() {
        let short_key = vec![0u8; 32];
        public_key_to_btc_address(&short_key);
    }

    #[test]
    fn test_btc_address_checksum_valid() {
        let pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();
        let address = public_key_to_btc_address(&pubkey);

        // Re-derive checksum from the first 21 bytes
        let payload = &address[0..21];
        let hash1 = sha256::Hash::hash(payload);
        let msg1 = Message::from_digest_slice(hash1.as_ref()).unwrap();
        let hash2 = sha256::Hash::hash(msg1.as_ref());
        let msg2 = Message::from_digest_slice(hash2.as_ref()).unwrap();
        let expected_checksum = &msg2.as_ref()[0..4];

        assert_eq!(&address[21..25], expected_checksum);
    }

    // ----------------------------------------------------------
    //  ETH address derivation tests
    // ----------------------------------------------------------

    #[test]
    fn test_eth_address_length() {
        // Random 64-byte uncompressed public key (sans 0x04 prefix)
        let pubkey = [0xABu8; 64];
        let address = public_key_to_eth_address(&pubkey);
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_eth_address_known_vector() {
        // Test vector: the Keccak-256 of 64 zero bytes,
        // then take last 20 bytes.
        let pubkey = [0u8; 64];
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey);
        let hash = hasher.finalize();
        let expected = &hash[12..];

        let address = public_key_to_eth_address(&pubkey);
        assert_eq!(address.as_slice(), expected);
    }

    #[test]
    fn test_eth_address_deterministic() {
        let pubkey = [0x42u8; 64];
        let addr1 = public_key_to_eth_address(&pubkey);
        let addr2 = public_key_to_eth_address(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[test]
    #[should_panic(expected = "Public key should be 64 bytes")]
    fn test_eth_address_invalid_pubkey_length() {
        let short_key = vec![0u8; 63];
        public_key_to_eth_address(&short_key);
    }

    // ----------------------------------------------------------
    //  PQ key validation tests
    // ----------------------------------------------------------

    #[test]
    fn test_validate_pq_pubkey_ml_dsa_44() {
        let key = vec![0u8; 1312];
        assert!(validate_pq_pubkey(&key));
    }

    #[test]
    fn test_validate_pq_pubkey_ml_dsa_65() {
        let key = vec![0u8; 1952];
        assert!(validate_pq_pubkey(&key));
    }

    #[test]
    fn test_validate_pq_pubkey_ml_dsa_87() {
        let key = vec![0u8; 2592];
        assert!(validate_pq_pubkey(&key));
    }

    #[test]
    fn test_validate_pq_pubkey_invalid_size() {
        let key = vec![0u8; 100];
        assert!(!validate_pq_pubkey(&key));
    }

    #[test]
    fn test_validate_pq_pubkey_empty() {
        assert!(!validate_pq_pubkey(&[]));
    }

    #[test]
    fn test_ml_dsa_level_name_44() {
        let key = vec![0u8; 1312];
        assert_eq!(ml_dsa_level_name(&key), "ML-DSA-44");
    }

    #[test]
    fn test_ml_dsa_level_name_65() {
        let key = vec![0u8; 1952];
        assert_eq!(ml_dsa_level_name(&key), "ML-DSA-65");
    }

    #[test]
    fn test_ml_dsa_level_name_87() {
        let key = vec![0u8; 2592];
        assert_eq!(ml_dsa_level_name(&key), "ML-DSA-87");
    }

    #[test]
    fn test_ml_dsa_level_name_unknown() {
        let key = vec![0u8; 999];
        assert_eq!(ml_dsa_level_name(&key), "Unknown");
    }

    // ----------------------------------------------------------
    //  PublicValuesStruct ABI encoding/decoding tests
    // ----------------------------------------------------------

    #[test]
    fn test_public_values_abi_roundtrip() {
        use alloy_sol_types::private::Bytes;

        let btc_addr = vec![0x00, 0x01, 0x02, 0x03];
        let pq_key = vec![0xAA; 1952];

        let encoded = PublicValuesStruct::abi_encode(&PublicValuesStruct {
            btc_address: Bytes::from(btc_addr.clone()),
            pq_pubkey: Bytes::from(pq_key.clone()),
        });

        let decoded = PublicValuesStruct::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.btc_address.as_ref(), btc_addr.as_slice());
        assert_eq!(decoded.pq_pubkey.as_ref(), pq_key.as_slice());
    }

    #[test]
    fn test_public_values_empty_fields() {
        use alloy_sol_types::private::Bytes;

        let encoded = PublicValuesStruct::abi_encode(&PublicValuesStruct {
            btc_address: Bytes::from(vec![]),
            pq_pubkey: Bytes::from(vec![]),
        });

        let decoded = PublicValuesStruct::abi_decode(&encoded).unwrap();
        assert!(decoded.btc_address.is_empty());
        assert!(decoded.pq_pubkey.is_empty());
    }

    #[test]
    fn test_public_values_large_pq_key() {
        use alloy_sol_types::private::Bytes;

        // ML-DSA-87 size key
        let btc_addr = vec![0x00; 25];
        let pq_key = vec![0xFF; 2592];

        let encoded = PublicValuesStruct::abi_encode(&PublicValuesStruct {
            btc_address: Bytes::from(btc_addr.clone()),
            pq_pubkey: Bytes::from(pq_key.clone()),
        });

        let decoded = PublicValuesStruct::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.btc_address.len(), 25);
        assert_eq!(decoded.pq_pubkey.len(), 2592);
    }

    #[test]
    fn test_public_values_sol_value_roundtrip() {
        use alloy_sol_types::SolValue;
        use alloy_sol_types::private::Bytes;

        let pv = PublicValuesStruct {
            btc_address: Bytes::from(vec![0x01, 0x02, 0x03]),
            pq_pubkey: Bytes::from(vec![0xAA; 1312]),
        };

        let encoded = pv.abi_encode();
        let decoded = <PublicValuesStruct as SolType>::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.btc_address.as_ref(), &[0x01, 0x02, 0x03]);
        assert_eq!(decoded.pq_pubkey.len(), 1312);
    }

    // ----------------------------------------------------------
    //  Additional edge case tests for completeness
    // ----------------------------------------------------------

    #[test]
    fn test_btc_address_with_03_prefix_key() {
        // Compressed public key starting with 0x03
        let pubkey = hex::decode(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
        ).unwrap();
        assert_eq!(pubkey.len(), 33);

        let address = public_key_to_btc_address(&pubkey);
        assert_eq!(address.len(), 25);
        assert_eq!(address[0], 0x00);
    }

    #[test]
    fn test_btc_address_different_keys_produce_different_addresses() {
        let pubkey1 = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();
        let pubkey2 = hex::decode(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
        ).unwrap();

        let addr1 = public_key_to_btc_address(&pubkey1);
        let addr2 = public_key_to_btc_address(&pubkey2);
        assert_ne!(addr1, addr2);
    }

    #[test]
    #[should_panic(expected = "Public key should be 33 bytes")]
    fn test_btc_address_too_long_key() {
        let long_key = vec![0u8; 65];
        public_key_to_btc_address(&long_key);
    }

    #[test]
    fn test_eth_address_different_keys_produce_different_addresses() {
        let pubkey1 = [0x01u8; 64];
        let pubkey2 = [0x02u8; 64];
        let addr1 = public_key_to_eth_address(&pubkey1);
        let addr2 = public_key_to_eth_address(&pubkey2);
        assert_ne!(addr1, addr2);
    }

    #[test]
    #[should_panic(expected = "Public key should be 64 bytes")]
    fn test_eth_address_too_long_key() {
        let long_key = vec![0u8; 65];
        public_key_to_eth_address(&long_key);
    }

    #[test]
    fn test_validate_pq_pubkey_boundary_sizes() {
        // Just below ML-DSA-44
        assert!(!validate_pq_pubkey(&vec![0u8; 1311]));
        // Just above ML-DSA-44
        assert!(!validate_pq_pubkey(&vec![0u8; 1313]));
        // Just below ML-DSA-65
        assert!(!validate_pq_pubkey(&vec![0u8; 1951]));
        // Just above ML-DSA-65
        assert!(!validate_pq_pubkey(&vec![0u8; 1953]));
        // Just below ML-DSA-87
        assert!(!validate_pq_pubkey(&vec![0u8; 2591]));
        // Just above ML-DSA-87
        assert!(!validate_pq_pubkey(&vec![0u8; 2593]));
    }

    #[test]
    fn test_constants() {
        assert_eq!(ML_DSA_65_PK_SIZE, 1952);
        assert_eq!(ML_DSA_65_SIG_SIZE, 3309);
        assert_eq!(ML_DSA_MIN_PK_SIZE, 1312);
        assert_eq!(ML_DSA_MAX_PK_SIZE, 2592);
    }
}

