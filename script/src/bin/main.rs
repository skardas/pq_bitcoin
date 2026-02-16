//! PQ Bitcoin — SP1 Host Script
//!
//! Generates a secp256k1 keypair, derives the BTC address, signs it,
//! generates an ML-DSA-65 post-quantum keypair, and feeds everything
//! into the SP1 zkVM program for proof generation.
//!
//! Usage:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! RUST_LOG=info cargo run --release -- --prove --prove-type=normal
//! RUST_LOG=info cargo run --release -- --prove --prove-type=groth
//! RUST_LOG=info cargo run --release -- --prove --prove-type=plonk
//! ```

use clap::{Parser, ValueEnum};
use hashes::{Hash, sha256};
use pq_bitcoin_lib::{ml_dsa_level_name, public_key_to_btc_address, validate_pq_pubkey};
use rand::TryRngCore;
use rand::rngs::OsRng;
use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey, Signing, ecdsa};
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin, include_elf};
use std::time::{SystemTime, UNIX_EPOCH};

// ML-DSA imports
use ml_dsa::ml_dsa_65;
use signature::Signer;

#[derive(ValueEnum, Clone, Debug)]
enum ProveType {
    Normal,
    Groth,
    Plonk,
}

pub const PROGRAM_ELF: &[u8] = include_elf!("pq_bitcoin-program");

fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    sec_key: [u8; 32],
) -> Result<(ecdsa::Signature, PublicKey, Vec<u8>), Error> {
    let sec_key = SecretKey::from_slice(&sec_key)?;
    let pub_key = sec_key.public_key(secp);
    let address = public_key_to_btc_address(&pub_key.serialize());

    let msg = sha256::Hash::hash(address.as_slice());
    let msg = Message::from_digest_slice(msg.as_ref())?;

    Ok((secp.sign_ecdsa(&msg, &sec_key), pub_key, address))
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,
    #[clap(long)]
    prove: bool,
    #[clap(long, value_enum, default_value_t = ProveType::Normal)]
    prove_type: ProveType,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();

    println!("Program size is : {}", PROGRAM_ELF.len());
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();

    // ── 1. Generate ECDSA keypair and sign ──────────────────────
    let secp = Secp256k1::new();
    let mut seckey = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seckey)
        .expect("cannot fill random bytes");

    let (signature, pub_key, address) = sign(&secp, seckey).unwrap();
    let serialized_pub_key = pub_key.serialize();
    let serialize_sig = signature.serialize_compact();

    println!("BTC Address (hex): {}", hex::encode(&address));
    println!("ECDSA Public Key:  {}", hex::encode(serialized_pub_key));

    // ── 2. Generate ML-DSA-65 post-quantum keypair ─────────────
    let mut rng = OsRng;
    let pq_signing_key = ml_dsa_65::SigningKey::generate(&mut rng);
    let pq_verifying_key = pq_signing_key.verifying_key();
    let pq_public_key_bytes = pq_verifying_key.as_ref().to_vec();

    // Validate the PQ public key format
    assert!(
        validate_pq_pubkey(&pq_public_key_bytes),
        "Generated PQ public key has invalid size: {}",
        pq_public_key_bytes.len()
    );

    println!(
        "PQ Key Type:       {}",
        ml_dsa_level_name(&pq_public_key_bytes)
    );
    println!("PQ Public Key Size: {} bytes", pq_public_key_bytes.len());

    // Optionally sign Something with the PQ key to prove it works
    let pq_sig = pq_signing_key.sign(&address);
    println!("PQ Signature Size: {} bytes", pq_sig.as_ref().len());

    // ── 3. Feed inputs to SP1 zkVM ─────────────────────────────
    stdin.write(&serialized_pub_key.to_vec());
    stdin.write(&address.to_vec());
    stdin.write(&serialize_sig.to_vec());
    stdin.write(&pq_public_key_bytes);

    if args.execute {
        let (_output, report) = client.execute(PROGRAM_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("Values are correct!");
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let (pk, vk) = client.setup(PROGRAM_ELF);
        let system_time = SystemTime::now();
        let start_time = system_time.duration_since(UNIX_EPOCH);
        println!("vk key {}", vk.bytes32());

        let proof = match args.prove_type {
            ProveType::Groth => client
                .prove(&pk, &stdin)
                .groth16()
                .run()
                .expect("failed to generate Groth16 proof"),

            ProveType::Plonk => client
                .prove(&pk, &stdin)
                .plonk()
                .run()
                .expect("failed to generate Plonk proof"),

            ProveType::Normal => client
                .prove(&pk, &stdin)
                .run()
                .expect("failed to generate normal proof"),
        };
        if matches!(args.prove_type, ProveType::Groth | ProveType::Plonk) {
            println!("Proof size {}", proof.bytes().len());
        }

        println!("Public values size {}", proof.public_values.to_vec().len());
        let system_time = SystemTime::now();
        println!(
            "Elapsed Proving time: {:?}",
            system_time.duration_since(UNIX_EPOCH).unwrap() - start_time.unwrap()
        );
        println!("Successfully generated proof!");
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
