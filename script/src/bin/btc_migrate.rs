use clap::Parser;
use ml_dsa::{KeyGen, MlDsa65, Seed};
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};

use pq_bitcoin_lib::op_return::{FLAG_GROTH16, MigrationPayload, PAYLOAD_SIZE};
use pq_bitcoin_lib::{ml_dsa_level_name, public_key_to_btc_address, validate_pq_pubkey};

#[derive(Parser)]
#[command(name = "btc-migrate")]
#[command(
    about = "Generate a Bitcoin OP_RETURN migration payload binding a BTC address to a post-quantum key"
)]
struct Args {
    /// Optional: hex-encoded ECDSA private key (32 bytes). If not provided, a random key is generated.
    #[arg(long)]
    privkey: Option<String>,

    /// Optional: hex-encoded PQ public key. If not provided, a random ML-DSA-65 keypair is generated.
    #[arg(long)]
    pq_pubkey: Option<String>,

    /// Output format: "hex" (raw OP_RETURN script) or "json" (structured output).
    #[arg(long, default_value = "json")]
    format: String,
}

fn main() {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     PQ Bitcoin — OP_RETURN Migration Payload Generator      ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── 1. ECDSA key ───────────────────────────────────────────
    let secp = Secp256k1::new();
    let secret_key = match &args.privkey {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key).expect("Invalid hex private key");
            SecretKey::from_slice(&bytes).expect("Invalid 32-byte private key")
        }
        None => {
            let mut rng = OsRng;
            let mut key_bytes = [0u8; 32];
            use rand::TryRngCore;
            rng.try_fill_bytes(&mut key_bytes)
                .expect("Random key generation failed");
            SecretKey::from_slice(&key_bytes).expect("Invalid random key")
        }
    };
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_pubkey = public_key.serialize(); // 33 bytes
    println!("ECDSA Public Key:  {}", hex::encode(compressed_pubkey));

    // ── 2. Derive BTC address ──────────────────────────────────
    let btc_address = public_key_to_btc_address(&compressed_pubkey).unwrap();
    println!("BTC Address:       {}", hex::encode(&btc_address));

    // ── 3. PQ keypair ──────────────────────────────────────────
    let pq_public_key_bytes = match &args.pq_pubkey {
        Some(hex_key) => hex::decode(hex_key).expect("Invalid hex PQ public key"),
        None => {
            let mut pq_seed = Seed::default();
            use rand::TryRngCore;
            OsRng
                .try_fill_bytes(&mut pq_seed)
                .expect("PQ seed generation failed");
            let kp = MlDsa65::from_seed(&pq_seed);
            kp.verifying_key().encode().to_vec()
        }
    };

    assert!(
        validate_pq_pubkey(&pq_public_key_bytes),
        "PQ public key has invalid size: {} bytes",
        pq_public_key_bytes.len()
    );
    println!(
        "PQ Key Type:       {} ({} bytes)",
        ml_dsa_level_name(&pq_public_key_bytes),
        pq_public_key_bytes.len()
    );

    // ── 4. Create mock proof placeholder ───────────────────────
    // In production, this would be the real STARK proof bytes.
    // For now, we hash the BTC address as a placeholder.
    let mock_proof = btc_address.clone();
    println!(
        "Proof:             (placeholder — run `cargo run --release --bin main -- --prove` for real proof)\n"
    );

    // ── 5. Build OP_RETURN payload ─────────────────────────────
    let payload = MigrationPayload::new(&pq_public_key_bytes, &mock_proof, FLAG_GROTH16);
    let encoded = payload.encode();

    println!(
        "── OP_RETURN Payload ({} bytes) ─────────────────────",
        PAYLOAD_SIZE
    );
    println!("Magic:             PQMG");
    println!("Version:           0x01");
    println!("PQ Key Hash:       {}", hex::encode(payload.pq_pubkey_hash));
    println!("Proof Hash:        {}", hex::encode(payload.proof_hash));
    println!(
        "Flags:             0x{:02x} (groth16={})",
        payload.flags,
        payload.is_groth16()
    );
    println!(
        "Level:             {} (0x{:02x})",
        payload.level_name(),
        payload.level
    );
    println!();

    // ── 6. Generate full OP_RETURN script ──────────────────────
    let script = payload.to_script();

    match args.format.as_str() {
        "hex" => {
            println!("{}", hex::encode(&script));
        }
        _ => {
            println!("── Output ──────────────────────────────────────────");
            println!("{{");
            println!("  \"btc_address\": \"0x{}\",", hex::encode(&btc_address));
            println!(
                "  \"pq_pubkey_hash\": \"0x{}\",",
                hex::encode(payload.pq_pubkey_hash)
            );
            println!(
                "  \"proof_hash\": \"0x{}\",",
                hex::encode(payload.proof_hash)
            );
            println!("  \"op_return_script\": \"0x{}\",", hex::encode(&script));
            println!("  \"op_return_payload\": \"0x{}\",", hex::encode(encoded));
            println!("  \"ml_dsa_level\": \"{}\",", payload.level_name());
            println!("  \"flags\": \"0x{:02x}\"", payload.flags);
            println!("}}");
        }
    }

    println!();
    println!("── How to use ──────────────────────────────────────");
    println!("1. Create a Bitcoin transaction spending from your address");
    println!("2. Add an OP_RETURN output with the script above");
    println!("3. Broadcast the transaction to the Bitcoin network");
    println!("4. Publish your full PQ public key off-chain (IPFS, website, etc.)");
    println!("5. Anyone can verify: SHA-256(your_pq_key) == committed hash");
}
