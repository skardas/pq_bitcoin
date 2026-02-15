#![no_main]

//! PQ Bitcoin — Ethereum Address Migration Circuit
//!
//! This zkVM program verifies ownership of an Ethereum EOA address
//! and binds it to a post-quantum (ML-DSA) public key.
//!
//! STARK Circuit Design (Paper Section 6.2):
//! - Public Inputs:  eth_address, pq_pubkey
//! - Private Inputs: uncompressed ECDSA public key (64 bytes), ECDSA signature
//!
//! The circuit validates:
//! 1. Keccak256(pubkey)[12..] == eth_address
//! 2. ECDSA signature is valid for the uncompressed public key
//! 3. PQ public key has a valid ML-DSA format

use alloy_sol_types::private::Bytes;
use alloy_sol_types::SolType;
use sha3::{Digest, Keccak256};

use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, Verification};
use pq_bitcoin_lib::{validate_pq_pubkey, PublicValuesStruct};
sp1_zkvm::entrypoint!(main);

/// Verify an ECDSA signature over a Keccak-256 hash of the message.
fn verify_eth_sig<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey_uncompressed: &[u8; 65],
) -> Result<bool, Error> {
    // Hash the message with Keccak-256 (Ethereum convention)
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    let msg = Message::from_digest_slice(&hash)?;

    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(pubkey_uncompressed)?;
    let result = secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok();
    Ok(result)
}

/// Derive Ethereum address from uncompressed public key (sans 0x04 prefix is 64 bytes).
fn derive_eth_address(pubkey_raw: &[u8]) -> Vec<u8> {
    assert_eq!(pubkey_raw.len(), 64, "Raw uncompressed public key (sans prefix) must be 64 bytes");
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_raw);
    let hash = hasher.finalize();
    hash[12..].to_vec()
}

pub fn main() {
    let secp = Secp256k1::new();

    // Read inputs from host
    let pubkey_vec: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();       // 65-byte uncompressed key (with 0x04 prefix)
    let eth_address: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();      // 20-byte ETH address
    let sig_serialized: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();   // 64-byte compact ECDSA sig
    let pq_public_key: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();    // ML-DSA public key

    // Convert to fixed-size arrays
    let pubkey_uncompressed: [u8; 65] = pubkey_vec
        .try_into()
        .expect("Uncompressed public key must be exactly 65 bytes (0x04 prefix + 64 bytes)");

    let sig: [u8; 64] = sig_serialized
        .try_into()
        .expect("ECDSA signature must be exactly 64 bytes");

    // ── 1. Verify ECDSA signature ──────────────────────────────
    assert!(verify_eth_sig(&secp, eth_address.as_slice(), sig, &pubkey_uncompressed).unwrap(),
        "ECDSA signature verification failed");

    // ── 2. Verify ETH address derivation (Keccak-256) ──────────
    // Use bytes 1..65 (strip 0x04 prefix) for key derivation
    let derived_eth_address = derive_eth_address(&pubkey_uncompressed[1..]);
    assert_eq!(derived_eth_address, eth_address,
        "Derived ETH address does not match provided address");

    // ── 3. Validate PQ public key format (ML-DSA) ──────────────
    assert!(validate_pq_pubkey(&pq_public_key),
        "PQ public key has invalid size: {} bytes", pq_public_key.len());

    // ── 4. Commit public values ────────────────────────────────
    // Note: We reuse PublicValuesStruct but the btc_address field holds the ETH address.
    // This is acceptable for the PoC; a production system would use a separate struct.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        btc_address: Bytes::from(eth_address),  // Reusing field name for ETH address
        pq_pubkey: Bytes::from(pq_public_key),
    });
    sp1_zkvm::io::commit_slice(&bytes);
}
