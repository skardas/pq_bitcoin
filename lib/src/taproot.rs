//! Taproot PQ Commitment — BIP-341 Script Tree for Post-Quantum Key Binding
//!
//! Implements Bitcoin Taproot (BIP-340/341) constructions for committing
//! a post-quantum public key hash into a Taproot output's script tree.
//!
//! # How It Works
//!
//! 1. User generates a Taproot internal key `P` (x-only, 32 bytes)
//! 2. We build a script leaf that commits to `SHA-256(pk_pq)`
//! 3. The leaf becomes part of a Taproot script tree
//! 4. The tweaked key `Q = P + t·G` commits to the script tree
//! 5. Funds sent to `Q` can be spent via the key path OR script path
//!
//! The script leaf uses:
//! ```text
//! OP_SHA256 <pq_pubkey_hash> OP_EQUALVERIFY OP_TRUE
//! ```
//!
//! To spend via the script path, the spender must reveal the PQ key
//! whose SHA-256 matches the committed hash.
//!
//! # BIP-341 Tagged Hash
//!
//! All hashes use the tagged scheme:
//! ```text
//! TaggedHash(tag, data) = SHA-256(SHA-256(tag) || SHA-256(tag) || data)
//! ```

use hashes::{sha256, Hash};

// ============================================================
//  Tagged Hash (BIP-340/341)
// ============================================================

/// Compute a BIP-340/341 tagged hash.
///
/// `TaggedHash(tag, data) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ data)`
///
/// This provides domain separation, ensuring different contexts
/// (TapLeaf, TapBranch, TapTweak, etc.) never collide.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let tag_bytes: &[u8; 32] = tag_hash.as_byte_array();

    // SHA-256(tag_hash || tag_hash || data)
    let mut engine = sha256::Hash::engine();
    use hashes::HashEngine;
    engine.input(tag_bytes);
    engine.input(tag_bytes);
    engine.input(data);
    let result = sha256::Hash::from_engine(engine);
    *result.as_byte_array()
}

// ============================================================
//  Taproot Leaf Version
// ============================================================

/// BIP-342 Tapscript leaf version (0xc0).
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

// ============================================================
//  Bitcoin Script Opcodes (subset needed for PQ commitment)
// ============================================================

/// OP_SHA256 — hash the top stack element with SHA-256.
pub const OP_SHA256: u8 = 0xa8;

/// OP_EQUALVERIFY — check equality and fail if not equal.
pub const OP_EQUALVERIFY: u8 = 0x88;

/// OP_TRUE (OP_1) — push the number 1 onto the stack.
pub const OP_TRUE: u8 = 0x51;

/// OP_CHECKSIG — verify a Schnorr signature (BIP-340).
pub const OP_CHECKSIG: u8 = 0xac;

/// OP_CHECKSEQUENCEVERIFY — relative timelock (BIP-112).
pub const OP_CSV: u8 = 0xb2;

/// OP_DROP — remove the top stack element.
pub const OP_DROP: u8 = 0x75;

// ============================================================
//  PQ Commitment Leaf Scripts
// ============================================================

/// Build a PQ commitment script that requires revealing the pre-image:
///
/// ```text
/// OP_SHA256 <32-byte hash> OP_EQUALVERIFY OP_TRUE
/// ```
///
/// To spend, the PQ public key must be pushed onto the stack.
/// The script then verifies `SHA-256(stack_top) == committed_hash`.
pub fn build_pq_commitment_script(pq_pubkey_hash: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(1 + 1 + 32 + 1 + 1);
    script.push(OP_SHA256);
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(pq_pubkey_hash);
    script.push(OP_EQUALVERIFY);
    script.push(OP_TRUE);
    script
}

/// Build a timelock fallback script:
///
/// ```text
/// <blocks> OP_CSV OP_DROP OP_TRUE
/// ```
///
/// This allows spending after `blocks` relative blocks, providing
/// a recovery path if the PQ migration doesn't happen in time.
pub fn build_timelock_script(blocks: u16) -> Vec<u8> {
    let mut script = Vec::new();
    if blocks <= 16 {
        // OP_1 through OP_16
        script.push(0x50 + blocks as u8);
    } else {
        // Push as little-endian integer
        let bytes = blocks.to_le_bytes();
        if blocks <= 0x7f {
            script.push(1); // push 1 byte
            script.push(bytes[0]);
        } else {
            script.push(2); // push 2 bytes
            script.extend_from_slice(&bytes);
        }
    }
    script.push(OP_CSV);
    script.push(OP_DROP);
    script.push(OP_TRUE);
    script
}

/// Build a Schnorr signature check script using x-only public key:
///
/// ```text
/// <32-byte x-only pubkey> OP_CHECKSIG
/// ```
pub fn build_checksig_script(x_only_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(1 + 32 + 1);
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(x_only_pubkey);
    script.push(OP_CHECKSIG);
    script
}

// ============================================================
//  TapLeaf Hash
// ============================================================

/// Compute the TapLeaf hash for a script.
///
/// ```text
/// TapLeaf = TaggedHash("TapLeaf", leaf_version || compact_size(script) || script)
/// ```
pub fn tap_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 5 + script.len());
    data.push(TAPSCRIPT_LEAF_VERSION);
    // Compact size encoding for script length
    compact_size_encode(script.len(), &mut data);
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &data)
}

/// Bitcoin compact size (varint) encoding.
pub fn compact_size_encode(size: usize, buf: &mut Vec<u8>) {
    if size < 253 {
        buf.push(size as u8);
    } else if size <= 0xFFFF {
        buf.push(253);
        buf.extend_from_slice(&(size as u16).to_le_bytes());
    } else if size <= 0xFFFF_FFFF {
        buf.push(254);
        buf.extend_from_slice(&(size as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&(size as u64).to_le_bytes());
    }
}

// ============================================================
//  TapBranch Hash
// ============================================================

/// Compute the TapBranch hash for two child nodes.
///
/// ```text
/// TapBranch = TaggedHash("TapBranch", sorted(left, right))
/// ```
///
/// Children are sorted lexicographically before concatenation.
pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    if left <= right {
        data[..32].copy_from_slice(left);
        data[32..].copy_from_slice(right);
    } else {
        data[..32].copy_from_slice(right);
        data[32..].copy_from_slice(left);
    }
    tagged_hash("TapBranch", &data)
}

// ============================================================
//  TapTweak
// ============================================================

/// Compute the TapTweak hash for key tweaking.
///
/// ```text
/// TapTweak = TaggedHash("TapTweak", internal_key || merkle_root)
/// ```
///
/// The `internal_key` is the 32-byte x-only public key.
/// The `merkle_root` is the root of the script tree (32 bytes),
/// or empty for a key-path-only output.
pub fn tap_tweak_hash(internal_key: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(internal_key);
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    tagged_hash("TapTweak", &data)
}

// ============================================================
//  PQ Migration Script Tree
// ============================================================

/// A complete Taproot script tree for PQ migration.
///
/// Contains two leaves:
/// - **Leaf 0 (PQ Commitment):** Requires PQ key pre-image to spend
/// - **Leaf 1 (Timelock Fallback):** Allows recovery spending after N blocks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PQMigrationTree {
    /// The PQ commitment script (leaf 0).
    pub pq_script: Vec<u8>,
    /// The timelock fallback script (leaf 1).
    pub timelock_script: Vec<u8>,
    /// TapLeaf hash of the PQ commitment script.
    pub pq_leaf_hash: [u8; 32],
    /// TapLeaf hash of the timelock script.
    pub timelock_leaf_hash: [u8; 32],
    /// Merkle root of the two-leaf tree.
    pub merkle_root: [u8; 32],
    /// The SHA-256 hash of the PQ public key committed in leaf 0.
    pub pq_pubkey_hash: [u8; 32],
    /// Timelock duration in blocks.
    pub timelock_blocks: u16,
}

impl PQMigrationTree {
    /// Build a PQ migration tree from a PQ public key and timelock.
    ///
    /// Computes SHA-256(pq_pubkey), builds both leaf scripts,
    /// and derives the Merkle root.
    pub fn new(pq_pubkey: &[u8], timelock_blocks: u16) -> Self {
        let pq_pubkey_hash = *sha256::Hash::hash(pq_pubkey).as_byte_array();

        let pq_script = build_pq_commitment_script(&pq_pubkey_hash);
        let timelock_script = build_timelock_script(timelock_blocks);

        let pq_leaf_hash = tap_leaf_hash(&pq_script);
        let timelock_leaf_hash = tap_leaf_hash(&timelock_script);

        let merkle_root = tap_branch_hash(&pq_leaf_hash, &timelock_leaf_hash);

        Self {
            pq_script,
            timelock_script,
            pq_leaf_hash,
            timelock_leaf_hash,
            merkle_root,
            pq_pubkey_hash,
            timelock_blocks,
        }
    }

    /// Compute the tweak hash for a given internal key.
    pub fn tweak_hash(&self, internal_key: &[u8; 32]) -> [u8; 32] {
        tap_tweak_hash(internal_key, Some(&self.merkle_root))
    }

    /// Generate the control block for spending via the PQ commitment leaf.
    ///
    /// Control block format:
    /// ```text
    /// <leaf_version | parity> <internal_key (32)> <sibling_hash (32)>
    /// ```
    pub fn pq_leaf_control_block(&self, internal_key: &[u8; 32], output_key_parity: u8) -> Vec<u8> {
        let mut cb = Vec::with_capacity(1 + 32 + 32);
        cb.push(TAPSCRIPT_LEAF_VERSION | (output_key_parity & 1));
        cb.extend_from_slice(internal_key);
        // Merkle proof: sibling of pq_leaf = timelock_leaf
        cb.extend_from_slice(&self.timelock_leaf_hash);
        cb
    }

    /// Generate the control block for spending via the timelock fallback leaf.
    pub fn timelock_leaf_control_block(&self, internal_key: &[u8; 32], output_key_parity: u8) -> Vec<u8> {
        let mut cb = Vec::with_capacity(1 + 32 + 32);
        cb.push(TAPSCRIPT_LEAF_VERSION | (output_key_parity & 1));
        cb.extend_from_slice(internal_key);
        // Merkle proof: sibling of timelock_leaf = pq_leaf
        cb.extend_from_slice(&self.pq_leaf_hash);
        cb
    }

    /// Verify that a PQ public key matches the committed hash in this tree.
    pub fn verify_pq_commitment(&self, pq_pubkey: &[u8]) -> bool {
        *sha256::Hash::hash(pq_pubkey).as_byte_array() == self.pq_pubkey_hash
    }
}

// ============================================================
//  Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------
    //  Tagged Hash
    // ----------------------------------------------------------

    #[test]
    fn test_tagged_hash_deterministic() {
        let h1 = tagged_hash("TapLeaf", b"hello");
        let h2 = tagged_hash("TapLeaf", b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tagged_hash_different_tags() {
        let h1 = tagged_hash("TapLeaf", b"data");
        let h2 = tagged_hash("TapBranch", b"data");
        assert_ne!(h1, h2); // Domain separation
    }

    #[test]
    fn test_tagged_hash_different_data() {
        let h1 = tagged_hash("TapLeaf", b"data1");
        let h2 = tagged_hash("TapLeaf", b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_tagged_hash_length() {
        let h = tagged_hash("TapLeaf", b"test");
        assert_eq!(h.len(), 32);
    }

    // ----------------------------------------------------------
    //  Compact Size Encoding
    // ----------------------------------------------------------

    #[test]
    fn test_compact_size_small() {
        let mut buf = Vec::new();
        compact_size_encode(35, &mut buf);
        assert_eq!(buf, vec![35]);
    }

    #[test]
    fn test_compact_size_medium() {
        let mut buf = Vec::new();
        compact_size_encode(300, &mut buf);
        assert_eq!(buf, vec![253, 0x2C, 0x01]); // 300 = 0x012C LE
    }

    #[test]
    fn test_compact_size_large() {
        let mut buf = Vec::new();
        compact_size_encode(70000, &mut buf);
        assert_eq!(buf.len(), 5); // prefix + 4-byte LE
        assert_eq!(buf[0], 254);
    }

    #[test]
    fn test_compact_size_zero() {
        let mut buf = Vec::new();
        compact_size_encode(0, &mut buf);
        assert_eq!(buf, vec![0]);
    }

    // ----------------------------------------------------------
    //  PQ Commitment Script
    // ----------------------------------------------------------

    #[test]
    fn test_pq_commitment_script_structure() {
        let hash = [0xAA; 32];
        let script = build_pq_commitment_script(&hash);
        assert_eq!(script[0], OP_SHA256);
        assert_eq!(script[1], 0x20); // push 32 bytes
        assert_eq!(&script[2..34], &hash);
        assert_eq!(script[34], OP_EQUALVERIFY);
        assert_eq!(script[35], OP_TRUE);
        assert_eq!(script.len(), 36);
    }

    #[test]
    fn test_pq_commitment_script_different_hashes() {
        let s1 = build_pq_commitment_script(&[0xAA; 32]);
        let s2 = build_pq_commitment_script(&[0xBB; 32]);
        assert_ne!(s1, s2);
    }

    // ----------------------------------------------------------
    //  Timelock Script
    // ----------------------------------------------------------

    #[test]
    fn test_timelock_script_small() {
        let script = build_timelock_script(10);
        assert_eq!(script[0], 0x50 + 10); // OP_10
        assert_eq!(script[1], OP_CSV);
        assert_eq!(script[2], OP_DROP);
        assert_eq!(script[3], OP_TRUE);
    }

    #[test]
    fn test_timelock_script_medium() {
        let script = build_timelock_script(100);
        assert_eq!(script[0], 1);   // push 1 byte
        assert_eq!(script[1], 100); // value
        assert_eq!(script[2], OP_CSV);
    }

    #[test]
    fn test_timelock_script_large() {
        let script = build_timelock_script(1000);
        assert_eq!(script[0], 2);    // push 2 bytes
        assert_eq!(script[1], 0xE8); // 1000 LE low byte
        assert_eq!(script[2], 0x03); // 1000 LE high byte
        assert_eq!(script[3], OP_CSV);
    }

    // ----------------------------------------------------------
    //  Checksig Script
    // ----------------------------------------------------------

    #[test]
    fn test_checksig_script_structure() {
        let pubkey = [0x02; 32];
        let script = build_checksig_script(&pubkey);
        assert_eq!(script[0], 0x20); // push 32 bytes
        assert_eq!(&script[1..33], &pubkey);
        assert_eq!(script[33], OP_CHECKSIG);
        assert_eq!(script.len(), 34);
    }

    // ----------------------------------------------------------
    //  TapLeaf Hash
    // ----------------------------------------------------------

    #[test]
    fn test_tap_leaf_hash_deterministic() {
        let script = build_pq_commitment_script(&[0xAA; 32]);
        let h1 = tap_leaf_hash(&script);
        let h2 = tap_leaf_hash(&script);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tap_leaf_hash_different_scripts() {
        let s1 = build_pq_commitment_script(&[0xAA; 32]);
        let s2 = build_pq_commitment_script(&[0xBB; 32]);
        assert_ne!(tap_leaf_hash(&s1), tap_leaf_hash(&s2));
    }

    #[test]
    fn test_tap_leaf_hash_length() {
        let script = build_timelock_script(144);
        let h = tap_leaf_hash(&script);
        assert_eq!(h.len(), 32);
    }

    // ----------------------------------------------------------
    //  TapBranch Hash
    // ----------------------------------------------------------

    #[test]
    fn test_tap_branch_hash_commutative() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        // Order shouldn't matter — branches are sorted
        assert_eq!(tap_branch_hash(&a, &b), tap_branch_hash(&b, &a));
    }

    #[test]
    fn test_tap_branch_hash_different_children() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        let c = [0x33; 32];
        assert_ne!(tap_branch_hash(&a, &b), tap_branch_hash(&a, &c));
    }

    // ----------------------------------------------------------
    //  TapTweak Hash
    // ----------------------------------------------------------

    #[test]
    fn test_tap_tweak_with_merkle_root() {
        let key = [0x02; 32];
        let root = [0xAA; 32];
        let tweak = tap_tweak_hash(&key, Some(&root));
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn test_tap_tweak_key_only() {
        let key = [0x02; 32];
        let tweak = tap_tweak_hash(&key, None);
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn test_tap_tweak_with_and_without_root_differ() {
        let key = [0x02; 32];
        let root = [0xAA; 32];
        let t1 = tap_tweak_hash(&key, Some(&root));
        let t2 = tap_tweak_hash(&key, None);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_tap_tweak_different_keys() {
        let root = [0xAA; 32];
        let t1 = tap_tweak_hash(&[0x01; 32], Some(&root));
        let t2 = tap_tweak_hash(&[0x02; 32], Some(&root));
        assert_ne!(t1, t2);
    }

    // ----------------------------------------------------------
    //  PQ Migration Tree
    // ----------------------------------------------------------

    #[test]
    fn test_migration_tree_builds() {
        let pq_key = vec![0xAA; 1952]; // ML-DSA-65
        let tree = PQMigrationTree::new(&pq_key, 144);
        assert_eq!(tree.timelock_blocks, 144);
        assert_eq!(tree.pq_pubkey_hash.len(), 32);
        assert_eq!(tree.merkle_root.len(), 32);
    }

    #[test]
    fn test_migration_tree_different_keys() {
        let t1 = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let t2 = PQMigrationTree::new(&vec![0xBB; 1952], 144);
        assert_ne!(t1.pq_pubkey_hash, t2.pq_pubkey_hash);
        assert_ne!(t1.merkle_root, t2.merkle_root);
    }

    #[test]
    fn test_migration_tree_different_timelocks() {
        let t1 = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let t2 = PQMigrationTree::new(&vec![0xAA; 1952], 288);
        assert_eq!(t1.pq_pubkey_hash, t2.pq_pubkey_hash); // same key
        assert_ne!(t1.merkle_root, t2.merkle_root); // different timelock
    }

    #[test]
    fn test_migration_tree_verify_commitment_valid() {
        let pq_key = vec![0xAA; 1952];
        let tree = PQMigrationTree::new(&pq_key, 144);
        assert!(tree.verify_pq_commitment(&pq_key));
    }

    #[test]
    fn test_migration_tree_verify_commitment_invalid() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        assert!(!tree.verify_pq_commitment(&vec![0xBB; 1952]));
    }

    #[test]
    fn test_migration_tree_tweak_hash() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let key = [0x02; 32];
        let tweak = tree.tweak_hash(&key);
        assert_eq!(tweak.len(), 32);
        // Should be same as computing manually
        let expected = tap_tweak_hash(&key, Some(&tree.merkle_root));
        assert_eq!(tweak, expected);
    }

    // ----------------------------------------------------------
    //  Control Blocks
    // ----------------------------------------------------------

    #[test]
    fn test_pq_leaf_control_block_structure() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let key = [0x02; 32];
        let cb = tree.pq_leaf_control_block(&key, 0);
        assert_eq!(cb.len(), 65); // 1 + 32 + 32
        assert_eq!(cb[0], TAPSCRIPT_LEAF_VERSION); // no parity bit
        assert_eq!(&cb[1..33], &key);
        assert_eq!(&cb[33..65], &tree.timelock_leaf_hash);
    }

    #[test]
    fn test_pq_leaf_control_block_with_parity() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let key = [0x02; 32];
        let cb = tree.pq_leaf_control_block(&key, 1);
        assert_eq!(cb[0], TAPSCRIPT_LEAF_VERSION | 1); // parity bit set
    }

    #[test]
    fn test_timelock_leaf_control_block_structure() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let key = [0x02; 32];
        let cb = tree.timelock_leaf_control_block(&key, 0);
        assert_eq!(cb.len(), 65);
        assert_eq!(&cb[33..65], &tree.pq_leaf_hash); // sibling is PQ leaf
    }

    #[test]
    fn test_control_blocks_have_different_siblings() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1952], 144);
        let key = [0x02; 32];
        let cb_pq = tree.pq_leaf_control_block(&key, 0);
        let cb_tl = tree.timelock_leaf_control_block(&key, 0);
        // Siblings should be different (each points to the other)
        assert_ne!(&cb_pq[33..65], &cb_tl[33..65]);
    }

    // ----------------------------------------------------------
    //  Edge cases
    // ----------------------------------------------------------

    #[test]
    fn test_migration_tree_small_key() {
        let tree = PQMigrationTree::new(&vec![0xAA; 1312], 10); // ML-DSA-44
        assert!(tree.verify_pq_commitment(&vec![0xAA; 1312]));
    }

    #[test]
    fn test_migration_tree_large_key() {
        let tree = PQMigrationTree::new(&vec![0xAA; 2592], 1000); // ML-DSA-87
        assert!(tree.verify_pq_commitment(&vec![0xAA; 2592]));
    }

    #[test]
    fn test_timelock_16_boundary() {
        // 16 is the max for OP_1..OP_16 encoding
        let s16 = build_timelock_script(16);
        assert_eq!(s16[0], 0x50 + 16); // OP_16

        let s17 = build_timelock_script(17);
        assert_eq!(s17[0], 1);  // push 1 byte
        assert_eq!(s17[1], 17); // value
    }

    #[test]
    fn test_timelock_128_boundary() {
        // 127 fits in 1 byte, 128 needs 2 bytes (sign bit)
        let s127 = build_timelock_script(127);
        assert_eq!(s127[0], 1); // push 1 byte

        let s128 = build_timelock_script(128);
        assert_eq!(s128[0], 2); // push 2 bytes
    }
}
