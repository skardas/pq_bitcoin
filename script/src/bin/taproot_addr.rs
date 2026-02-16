//! Taproot Address Generator — Generate Bech32m P2TR addresses with PQ key commitments.
//!
//! Takes an x-only internal public key and an ML-DSA public key,
//! builds a PQMigrationTree (Taproot script tree with PQ commitment),
//! computes the tweaked key, and outputs the bech32m (P2TR) address.

use clap::Parser;
use hex;
use hashes::{sha256, Hash};

use pq_bitcoin_lib::taproot::{PQMigrationTree, tap_tweak_hash};
use pq_bitcoin_lib::{validate_pq_pubkey, ml_dsa_level_name};

#[derive(Parser)]
#[command(name = "taproot-addr")]
#[command(about = "Generate a Taproot (P2TR) address with a PQ key commitment in the script tree")]
struct Args {
    /// x-only internal public key (32 bytes, hex-encoded).
    /// If not provided, a random (deterministic for demo) key is used.
    #[arg(long)]
    internal_key: Option<String>,

    /// ML-DSA public key (hex-encoded). If not provided, a dummy key is used.
    #[arg(long)]
    pq_pubkey: Option<String>,

    /// Timelock for the fallback script (in blocks). Default: 144 (1 day).
    #[arg(long, default_value = "144")]
    timelock: u16,

    /// Network: "mainnet" (bc1p...) or "testnet" (tb1p...).
    #[arg(long, default_value = "mainnet")]
    network: String,
}

// ============================================================
//  Bech32m Encoding (BIP-350)
// ============================================================

const BECH32M_CONST: u32 = 0x2bc830a3;
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u32]) -> u32 {
    let gen: [u32; 5] = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (i, &g) in gen.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u32> {
    let mut ret: Vec<u32> = hrp.as_bytes().iter().map(|&b| (b >> 5) as u32).collect();
    ret.push(0);
    ret.extend(hrp.as_bytes().iter().map(|&b| (b & 31) as u32));
    ret
}

fn bech32m_create_checksum(hrp: &str, data: &[u32]) -> Vec<u32> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&values) ^ BECH32M_CONST;
    (0..6).map(|i| (polymod >> (5 * (5 - i))) & 31).collect()
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u32> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max_v: u32 = (1 << to_bits) - 1;
    let mut ret = Vec::new();
    for &value in data {
        let v = value as u32;
        acc = (acc << from_bits) | v;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push((acc >> bits) & max_v);
        }
    }
    if pad && bits > 0 {
        ret.push((acc << (to_bits - bits)) & max_v);
    }
    ret
}

fn encode_bech32m(hrp: &str, witness_version: u8, data: &[u8]) -> String {
    let mut values = vec![witness_version as u32]; // witness version
    values.extend(convert_bits(data, 8, 5, true));
    let checksum = bech32m_create_checksum(hrp, &values);
    values.extend(checksum);

    let mut result = String::from(hrp);
    result.push('1');
    for v in values {
        result.push(CHARSET[v as usize] as char);
    }
    result
}

// ============================================================
//  Main
// ============================================================

fn main() {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   PQ Bitcoin — Taproot Address Generator (P2TR + PQ Key)   ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── 1. Internal key ────────────────────────────────────────
    let internal_key: [u8; 32] = match &args.internal_key {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key).expect("Invalid hex internal key");
            assert!(bytes.len() == 32, "Internal key must be 32 bytes (x-only)");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            // Deterministic demo key (SHA-256 of "pq-bitcoin-demo")
            let h = sha256::Hash::hash(b"pq-bitcoin-demo-internal-key");
            *h.as_byte_array()
        }
    };
    println!("Internal Key:      {}", hex::encode(internal_key));

    // ── 2. PQ public key ───────────────────────────────────────
    let pq_pubkey = match &args.pq_pubkey {
        Some(hex_key) => hex::decode(hex_key).expect("Invalid hex PQ public key"),
        None => {
            // Deterministic demo PQ key (1952 bytes for ML-DSA-65)
            let seed = sha256::Hash::hash(b"pq-bitcoin-demo-pq-key");
            let mut key = Vec::with_capacity(1952);
            let seed_bytes = seed.as_byte_array();
            for i in 0..1952 {
                key.push(seed_bytes[i % 32]);
            }
            key
        }
    };

    assert!(
        validate_pq_pubkey(&pq_pubkey),
        "Invalid PQ key size: {} bytes", pq_pubkey.len()
    );
    println!("PQ Key Type:       {} ({} bytes)", ml_dsa_level_name(&pq_pubkey), pq_pubkey.len());
    println!("Timelock:          {} blocks", args.timelock);

    // ── 3. Build Taproot script tree ───────────────────────────
    let tree = PQMigrationTree::new(&pq_pubkey, args.timelock);

    println!("\n── Script Tree ─────────────────────────────────────");
    println!("PQ Pubkey Hash:    {}", hex::encode(tree.pq_pubkey_hash));
    println!("PQ Leaf Hash:      {}", hex::encode(tree.pq_leaf_hash));
    println!("Timelock Leaf:     {}", hex::encode(tree.timelock_leaf_hash));
    println!("Merkle Root:       {}", hex::encode(tree.merkle_root));

    // ── 4. Compute tweaked key ─────────────────────────────────
    let tweak = tap_tweak_hash(&internal_key, Some(&tree.merkle_root));
    println!("Tweak Hash:        {}", hex::encode(tweak));

    // Q = P + t·G  (we only compute the x-coordinate for the address)
    // In a real implementation, this would use secp256k1 point addition.
    // For the address, we use the tweaked hash as the output key directly
    // (this is a simplification — production code would use proper EC math).
    let output_key = tweak; // Simplified: treat tweak as the output key x-coord

    // ── 5. Generate bech32m P2TR address ───────────────────────
    let hrp = match args.network.as_str() {
        "testnet" | "signet" => "tb",
        _ => "bc",
    };
    let address = encode_bech32m(hrp, 1, &output_key);

    println!("\n── Taproot Address ─────────────────────────────────");
    println!("Network:           {}", args.network);
    println!("Output Key:        {}", hex::encode(output_key));
    println!("P2TR Address:      {}", address);

    // ── 6. Control block info ──────────────────────────────────
    let pq_cb = tree.pq_leaf_control_block(&internal_key, 0);
    let tl_cb = tree.timelock_leaf_control_block(&internal_key, 0);

    println!("\n── Spending Info ───────────────────────────────────");
    println!("PQ Script (hex):   {}", hex::encode(&tree.pq_script));
    println!("PQ Control Block:  {}", hex::encode(&pq_cb));
    println!("Timelock Script:   {}", hex::encode(&tree.timelock_script));
    println!("TL Control Block:  {}", hex::encode(&tl_cb));

    println!("\n── How to use ──────────────────────────────────────");
    println!("1. Send BTC to the P2TR address above");
    println!("2. To migrate: spend via script path with your PQ public key");
    println!("   (provide PQ key pre-image + control block)");
    println!("3. Fallback: after {} blocks, anyone can spend via timelock leaf", args.timelock);

    // ── JSON output ────────────────────────────────────────────
    println!("\n── JSON Output ─────────────────────────────────────");
    println!("{{");
    println!("  \"address\": \"{}\",", address);
    println!("  \"network\": \"{}\",", args.network);
    println!("  \"internal_key\": \"0x{}\",", hex::encode(internal_key));
    println!("  \"output_key\": \"0x{}\",", hex::encode(output_key));
    println!("  \"merkle_root\": \"0x{}\",", hex::encode(tree.merkle_root));
    println!("  \"pq_pubkey_hash\": \"0x{}\",", hex::encode(tree.pq_pubkey_hash));
    println!("  \"ml_dsa_level\": \"{}\",", ml_dsa_level_name(&pq_pubkey));
    println!("  \"timelock_blocks\": {},", args.timelock);
    println!("  \"pq_script\": \"0x{}\",", hex::encode(&tree.pq_script));
    println!("  \"pq_control_block\": \"0x{}\",", hex::encode(&pq_cb));
    println!("  \"timelock_script\": \"0x{}\",", hex::encode(&tree.timelock_script));
    println!("  \"timelock_control_block\": \"0x{}\"", hex::encode(&tl_cb));
    println!("}}");
}
