#![no_main]

use alloy_sol_types::SolType;
use alloy_sol_types::private::Bytes;

use hashes::{Hash, sha256};
use pq_bitcoin_lib::{PublicValuesStruct, public_key_to_btc_address, validate_pq_pubkey};
use secp256k1::{Error, Message, PublicKey, Secp256k1, Verification, ecdsa};
sp1_zkvm::entrypoint!(main);

fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey: [u8; 33],
) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;
    let result = secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok();
    Ok(result)
}

pub fn main() {
    let secp = Secp256k1::new();
    let pubkey_vec: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    // Convert Vec<u8> into [u8; 33]
    let pubkey: [u8; 33] = pubkey_vec
        .try_into()
        .expect("Compressed public key must be exactly 33 bytes");
    let btc_address: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let sig_serialized: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let pq_public_key: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    // ── 1. Verify ECDSA signature ──────────────────────────────
    assert!(
        verify(
            &secp,
            btc_address.as_slice(),
            sig_serialized.try_into().unwrap(),
            pubkey
        )
        .unwrap(),
        "ECDSA signature verification failed"
    );

    // ── 2. Verify BTC address derivation ───────────────────────
    let derived_btc_address = public_key_to_btc_address(&pubkey);
    assert_eq!(
        derived_btc_address, btc_address,
        "Derived BTC address does not match provided address"
    );

    // ── 3. Validate PQ public key format (ML-DSA) ──────────────
    assert!(
        validate_pq_pubkey(&pq_public_key),
        "PQ public key has invalid size: {} bytes. Expected ML-DSA-44 (1312), ML-DSA-65 (1952), or ML-DSA-87 (2592).",
        pq_public_key.len()
    );

    // ── 4. Commit public values ────────────────────────────────
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        btc_address: Bytes::from(btc_address),
        pq_pubkey: Bytes::from(pq_public_key),
    });
    sp1_zkvm::io::commit_slice(&bytes);
}
