//! PQ Bitcoin — EVM Proof Generator
//!
//! Generates EVM-compatible proofs (Groth16 or PLONK) and saves fixture
//! JSON files for Solidity contract testing.
//!
//! Usage:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use hashes::{Hash, sha256};
use pq_bitcoin_lib::{
    PublicValuesStruct, ml_dsa_level_name, public_key_to_btc_address, validate_pq_pubkey,
};
use rand::TryRngCore;
use rand::rngs::OsRng;
use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey, Signing, ecdsa};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, include_elf,
};
use std::path::PathBuf;

// ML-DSA imports
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa65, Seed};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const PQ_BITCOIN_ELF: &[u8] = include_elf!("pq_bitcoin-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 PQ Bitcoin proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1PQBitcoinProofFixture {
    btc_address: String,
    pq_pubkey: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    sec_key: [u8; 32],
) -> Result<(ecdsa::Signature, PublicKey, Vec<u8>), Error> {
    let sec_key = SecretKey::from_slice(&sec_key)?;
    let pub_key = sec_key.public_key(secp);
    let address = public_key_to_btc_address(&pub_key.serialize()).unwrap();

    let msg = sha256::Hash::hash(address.as_slice());
    let msg = Message::from_digest_slice(msg.as_ref())?;

    Ok((secp.sign_ecdsa(&msg, &sec_key), pub_key, address))
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the program.
    let (pk, vk) = client.setup(PQ_BITCOIN_ELF);

    // ── 1. Generate ECDSA keypair and sign ──────────────────────
    let secp = Secp256k1::new();
    let mut seckey = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seckey)
        .expect("cannot fill random bytes");

    let (sig, pub_key, address) = sign(&secp, seckey).unwrap();
    let serialized_pub_key = pub_key.serialize();
    let serialize_sig = sig.serialize_compact();

    println!("BTC Address (hex): {}", hex::encode(&address));

    // ── 2. Generate ML-DSA-65 post-quantum keypair ─────────────
    let mut pq_seed = Seed::default();
    OsRng
        .try_fill_bytes(&mut pq_seed)
        .expect("cannot fill random bytes for PQ seed");
    let kp = MlDsa65::from_seed(&pq_seed);
    let pq_signing_key = kp.signing_key().clone();
    let pq_verifying_key = kp.verifying_key().clone();
    let pq_public_key_bytes = pq_verifying_key.encode().to_vec();

    assert!(
        validate_pq_pubkey(&pq_public_key_bytes),
        "Generated PQ public key has invalid size: {}",
        pq_public_key_bytes.len()
    );
    println!(
        "PQ Key Type: {} ({} bytes)",
        ml_dsa_level_name(&pq_public_key_bytes),
        pq_public_key_bytes.len()
    );

    // Sign the address with PQ key to demonstrate it works
    let _pq_sig = pq_signing_key.sign(&address);

    // ── 3. Feed inputs to SP1 zkVM ─────────────────────────────
    let mut stdin = SP1Stdin::new();
    stdin.write(&serialized_pub_key.to_vec());
    stdin.write(&address.to_vec());
    stdin.write(&serialize_sig.to_vec());
    stdin.write(&pq_public_key_bytes);

    println!("Proof System: {:?}", args.system);

    // Generate the proof based on the selected proof system.
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, args.system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let PublicValuesStruct {
        btc_address,
        pq_pubkey,
    } = PublicValuesStruct::abi_decode(bytes).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1PQBitcoinProofFixture {
        btc_address: format!("0x{}", hex::encode(&btc_address)),
        pq_pubkey: format!("0x{}", hex::encode(&pq_pubkey)),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    println!("Verification Key: {}", fixture.vkey);
    println!("BTC Address: {}", fixture.btc_address);
    println!("PQ Pubkey length: {} bytes", pq_pubkey.len());
    println!("Public Values length: {} bytes", bytes.len());
    println!("Proof length: {} bytes", proof.bytes().len());

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    println!(
        "Fixture saved to contracts/src/fixtures/{:?}-fixture.json",
        system
    );
}
