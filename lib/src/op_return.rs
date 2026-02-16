//! OP_RETURN Migration Payload for Bitcoin On-Chain Registry
//!
//! Bitcoin has no smart contracts, so we embed migration commitments
//! in OP_RETURN outputs (up to 80 bytes). The payload commits to:
//! - SHA-256 hash of the PQ public key
//! - SHA-256 hash of the STARK proof
//!
//! Full PQ key (1952+ bytes) is published off-chain; anyone can verify
//! the hash matches the on-chain commitment.
//!
//! Payload format (69 bytes):
//! ┌──────────┬────────┬──────────────────┬──────────────────┬───────┬─────────┐
//! │ Magic(4) │ Ver(1) │ PQ Key Hash (32) │ Proof Hash (32)  │Flg(1) │Level(1) │
//! │ "PQMG"   │ 0x01   │ SHA-256(pk_pq)   │ SHA-256(π_STARK) │       │         │
//! └──────────┴────────┴──────────────────┴──────────────────┴───────┴─────────┘
//!                                                              = 71 bytes

use hashes::{Hash, sha256};

/// Magic bytes identifying a PQ migration OP_RETURN payload.
pub const MAGIC: [u8; 4] = *b"PQMG";

/// Current payload version.
pub const VERSION: u8 = 0x01;

/// Total payload size in bytes.
pub const PAYLOAD_SIZE: usize = 71;

/// Maximum OP_RETURN data size in Bitcoin.
pub const OP_RETURN_MAX: usize = 80;

// ── Flag bits ──────────────────────────────────────────────────

/// Flag: proof was generated with Groth16 wrapping.
pub const FLAG_GROTH16: u8 = 0x01;

/// Flag: proof was generated with PLONK wrapping.
pub const FLAG_PLONK: u8 = 0x02;

/// Flag: dual-signature mode (exposed key path).
pub const FLAG_DUAL_SIG: u8 = 0x04;

// ── ML-DSA Level Identifiers ───────────────────────────────────

/// ML-DSA-44 (NIST Level 2, 1312-byte public key).
pub const LEVEL_ML_DSA_44: u8 = 0x01;

/// ML-DSA-65 (NIST Level 3, 1952-byte public key).
pub const LEVEL_ML_DSA_65: u8 = 0x02;

/// ML-DSA-87 (NIST Level 5, 2592-byte public key).
pub const LEVEL_ML_DSA_87: u8 = 0x03;

// ============================================================
//  Migration Payload
// ============================================================

/// A PQ migration commitment payload for OP_RETURN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPayload {
    /// SHA-256 hash of the full ML-DSA public key.
    pub pq_pubkey_hash: [u8; 32],
    /// SHA-256 hash of the STARK proof.
    pub proof_hash: [u8; 32],
    /// Flags (proof type, dual-sig mode, etc.).
    pub flags: u8,
    /// ML-DSA security level identifier.
    pub level: u8,
}

impl MigrationPayload {
    /// Create a new migration payload from raw PQ key and proof bytes.
    ///
    /// Computes SHA-256 hashes of both inputs and auto-detects the ML-DSA level
    /// from the public key length.
    pub fn new(pq_pubkey: &[u8], proof: &[u8], flags: u8) -> Self {
        let pq_pubkey_hash = sha256::Hash::hash(pq_pubkey);
        let proof_hash = sha256::Hash::hash(proof);

        let level = match pq_pubkey.len() {
            1312 => LEVEL_ML_DSA_44,
            1952 => LEVEL_ML_DSA_65,
            2592 => LEVEL_ML_DSA_87,
            _ => 0x00, // Unknown
        };

        Self {
            pq_pubkey_hash: *pq_pubkey_hash.as_byte_array(),
            proof_hash: *proof_hash.as_byte_array(),
            flags,
            level,
        }
    }

    /// Create a payload from pre-computed hashes.
    pub fn from_hashes(
        pq_pubkey_hash: [u8; 32],
        proof_hash: [u8; 32],
        flags: u8,
        level: u8,
    ) -> Self {
        Self {
            pq_pubkey_hash,
            proof_hash,
            flags,
            level,
        }
    }

    /// Encode the payload into a 71-byte OP_RETURN data buffer.
    ///
    /// Format: MAGIC (4) | VERSION (1) | pq_hash (32) | proof_hash (32) | flags (1) | level (1)
    pub fn encode(&self) -> [u8; PAYLOAD_SIZE] {
        let mut buf = [0u8; PAYLOAD_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = VERSION;
        buf[5..37].copy_from_slice(&self.pq_pubkey_hash);
        buf[37..69].copy_from_slice(&self.proof_hash);
        buf[69] = self.flags;
        buf[70] = self.level;
        buf
    }

    /// Decode a payload from a byte slice.
    ///
    /// Returns `None` if the magic bytes or version don't match,
    /// or if the slice is too short.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < PAYLOAD_SIZE {
            return None;
        }
        if data[0..4] != MAGIC {
            return None;
        }
        if data[4] != VERSION {
            return None;
        }

        let mut pq_pubkey_hash = [0u8; 32];
        let mut proof_hash = [0u8; 32];
        pq_pubkey_hash.copy_from_slice(&data[5..37]);
        proof_hash.copy_from_slice(&data[37..69]);

        Some(Self {
            pq_pubkey_hash,
            proof_hash,
            flags: data[69],
            level: data[70],
        })
    }

    /// Verify that a PQ public key matches the committed hash.
    pub fn verify_pq_commitment(&self, pq_pubkey: &[u8]) -> bool {
        let hash = sha256::Hash::hash(pq_pubkey);
        *hash.as_byte_array() == self.pq_pubkey_hash
    }

    /// Verify that a proof matches the committed hash.
    pub fn verify_proof_commitment(&self, proof: &[u8]) -> bool {
        let hash = sha256::Hash::hash(proof);
        *hash.as_byte_array() == self.proof_hash
    }

    /// Check if this payload uses Groth16 proof wrapping.
    pub fn is_groth16(&self) -> bool {
        self.flags & FLAG_GROTH16 != 0
    }

    /// Check if this payload uses PLONK proof wrapping.
    pub fn is_plonk(&self) -> bool {
        self.flags & FLAG_PLONK != 0
    }

    /// Check if this is a dual-signature migration (exposed key path).
    pub fn is_dual_sig(&self) -> bool {
        self.flags & FLAG_DUAL_SIG != 0
    }

    /// Get the human-readable ML-DSA level name.
    pub fn level_name(&self) -> &'static str {
        match self.level {
            LEVEL_ML_DSA_44 => "ML-DSA-44",
            LEVEL_ML_DSA_65 => "ML-DSA-65",
            LEVEL_ML_DSA_87 => "ML-DSA-87",
            _ => "Unknown",
        }
    }

    /// Build the full OP_RETURN script: OP_RETURN <payload>.
    ///
    /// Bitcoin script format:
    /// - 0x6a = OP_RETURN
    /// - 0x4c 0x47 = OP_PUSHDATA1, 71 bytes
    /// - <71 bytes of payload>
    pub fn to_script(&self) -> Vec<u8> {
        let payload = self.encode();
        let mut script = Vec::with_capacity(2 + 1 + PAYLOAD_SIZE);
        script.push(0x6a); // OP_RETURN
        script.push(0x4c); // OP_PUSHDATA1
        script.push(PAYLOAD_SIZE as u8); // length
        script.extend_from_slice(&payload);
        script
    }

    /// Check if a raw script is a PQ migration OP_RETURN.
    ///
    /// Looks for: 0x6a (OP_RETURN) followed by push of data starting with "PQMG".
    pub fn is_migration_script(script: &[u8]) -> bool {
        if script.is_empty() || script[0] != 0x6a {
            return false;
        }
        // OP_RETURN + OP_PUSHDATA1 + len + payload
        if script.len() >= 3 + PAYLOAD_SIZE && script[1] == 0x4c && script[2] == PAYLOAD_SIZE as u8
        {
            return script[3..7] == MAGIC;
        }
        // OP_RETURN + direct push (len byte) + payload
        if script.len() >= 2 + PAYLOAD_SIZE && script[1] == PAYLOAD_SIZE as u8 {
            return script[2..6] == MAGIC;
        }
        false
    }

    /// Parse a migration payload from a raw Bitcoin script.
    pub fn from_script(script: &[u8]) -> Option<Self> {
        if !Self::is_migration_script(script) {
            return None;
        }
        // OP_PUSHDATA1 variant
        if script.len() >= 3 + PAYLOAD_SIZE && script[1] == 0x4c {
            return Self::decode(&script[3..]);
        }
        // Direct push variant
        if script.len() >= 2 + PAYLOAD_SIZE {
            return Self::decode(&script[2..]);
        }
        None
    }
}

// ============================================================
//  Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pq_key() -> Vec<u8> {
        vec![0xAA; 1952] // ML-DSA-65 size
    }

    fn sample_proof() -> Vec<u8> {
        vec![0xBB; 256]
    }

    // ----------------------------------------------------------
    //  Encode / Decode
    // ----------------------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let encoded = payload.encode();
        let decoded = MigrationPayload::decode(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_size_within_op_return() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let encoded = payload.encode();
        assert_eq!(encoded.len(), PAYLOAD_SIZE);
        assert!(encoded.len() <= OP_RETURN_MAX);
    }

    #[test]
    fn test_magic_bytes() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let encoded = payload.encode();
        assert_eq!(&encoded[0..4], b"PQMG");
    }

    #[test]
    fn test_version_byte() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let encoded = payload.encode();
        assert_eq!(encoded[4], VERSION);
    }

    #[test]
    fn test_decode_wrong_magic() {
        let mut encoded = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0).encode();
        encoded[0] = 0xFF; // corrupt magic
        assert!(MigrationPayload::decode(&encoded).is_none());
    }

    #[test]
    fn test_decode_wrong_version() {
        let mut encoded = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0).encode();
        encoded[4] = 0xFF; // unknown version
        assert!(MigrationPayload::decode(&encoded).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        let short_data = vec![0u8; PAYLOAD_SIZE - 1];
        assert!(MigrationPayload::decode(&short_data).is_none());
    }

    #[test]
    fn test_decode_empty() {
        assert!(MigrationPayload::decode(&[]).is_none());
    }

    // ----------------------------------------------------------
    //  Hash commitment verification
    // ----------------------------------------------------------

    #[test]
    fn test_verify_pq_commitment_valid() {
        let pq_key = sample_pq_key();
        let payload = MigrationPayload::new(&pq_key, &sample_proof(), 0);
        assert!(payload.verify_pq_commitment(&pq_key));
    }

    #[test]
    fn test_verify_pq_commitment_invalid() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let wrong_key = vec![0xCC; 1952];
        assert!(!payload.verify_pq_commitment(&wrong_key));
    }

    #[test]
    fn test_verify_proof_commitment_valid() {
        let proof = sample_proof();
        let payload = MigrationPayload::new(&sample_pq_key(), &proof, 0);
        assert!(payload.verify_proof_commitment(&proof));
    }

    #[test]
    fn test_verify_proof_commitment_invalid() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let wrong_proof = vec![0xDD; 128];
        assert!(!payload.verify_proof_commitment(&wrong_proof));
    }

    // ----------------------------------------------------------
    //  ML-DSA level auto-detection
    // ----------------------------------------------------------

    #[test]
    fn test_level_ml_dsa_44() {
        let payload = MigrationPayload::new(&vec![0u8; 1312], &sample_proof(), 0);
        assert_eq!(payload.level, LEVEL_ML_DSA_44);
        assert_eq!(payload.level_name(), "ML-DSA-44");
    }

    #[test]
    fn test_level_ml_dsa_65() {
        let payload = MigrationPayload::new(&vec![0u8; 1952], &sample_proof(), 0);
        assert_eq!(payload.level, LEVEL_ML_DSA_65);
        assert_eq!(payload.level_name(), "ML-DSA-65");
    }

    #[test]
    fn test_level_ml_dsa_87() {
        let payload = MigrationPayload::new(&vec![0u8; 2592], &sample_proof(), 0);
        assert_eq!(payload.level, LEVEL_ML_DSA_87);
        assert_eq!(payload.level_name(), "ML-DSA-87");
    }

    #[test]
    fn test_level_unknown() {
        let payload = MigrationPayload::new(&vec![0u8; 999], &sample_proof(), 0);
        assert_eq!(payload.level, 0x00);
        assert_eq!(payload.level_name(), "Unknown");
    }

    // ----------------------------------------------------------
    //  Flags
    // ----------------------------------------------------------

    #[test]
    fn test_flags_groth16() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_GROTH16);
        assert!(payload.is_groth16());
        assert!(!payload.is_plonk());
        assert!(!payload.is_dual_sig());
    }

    #[test]
    fn test_flags_plonk() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_PLONK);
        assert!(!payload.is_groth16());
        assert!(payload.is_plonk());
        assert!(!payload.is_dual_sig());
    }

    #[test]
    fn test_flags_dual_sig() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_DUAL_SIG);
        assert!(!payload.is_groth16());
        assert!(!payload.is_plonk());
        assert!(payload.is_dual_sig());
    }

    #[test]
    fn test_flags_combined() {
        let flags = FLAG_GROTH16 | FLAG_DUAL_SIG;
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), flags);
        assert!(payload.is_groth16());
        assert!(!payload.is_plonk());
        assert!(payload.is_dual_sig());
    }

    #[test]
    fn test_flags_none() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        assert!(!payload.is_groth16());
        assert!(!payload.is_plonk());
        assert!(!payload.is_dual_sig());
    }

    #[test]
    fn test_flags_preserved_through_encode_decode() {
        let flags = FLAG_PLONK | FLAG_DUAL_SIG;
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), flags);
        let decoded = MigrationPayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded.flags, flags);
        assert!(decoded.is_plonk());
        assert!(decoded.is_dual_sig());
    }

    // ----------------------------------------------------------
    //  Script generation / parsing
    // ----------------------------------------------------------

    #[test]
    fn test_to_script() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let script = payload.to_script();
        assert_eq!(script[0], 0x6a); // OP_RETURN
        assert_eq!(script[1], 0x4c); // OP_PUSHDATA1
        assert_eq!(script[2], PAYLOAD_SIZE as u8);
        assert_eq!(&script[3..7], b"PQMG");
    }

    #[test]
    fn test_is_migration_script_valid() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let script = payload.to_script();
        assert!(MigrationPayload::is_migration_script(&script));
    }

    #[test]
    fn test_is_migration_script_not_op_return() {
        let mut script = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0).to_script();
        script[0] = 0x00; // not OP_RETURN
        assert!(!MigrationPayload::is_migration_script(&script));
    }

    #[test]
    fn test_is_migration_script_wrong_magic() {
        let mut script = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0).to_script();
        script[3] = 0xFF; // corrupt magic
        assert!(!MigrationPayload::is_migration_script(&script));
    }

    #[test]
    fn test_is_migration_script_empty() {
        assert!(!MigrationPayload::is_migration_script(&[]));
    }

    #[test]
    fn test_from_script_roundtrip() {
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_GROTH16);
        let script = payload.to_script();
        let parsed = MigrationPayload::from_script(&script).unwrap();
        assert_eq!(payload, parsed);
    }

    #[test]
    fn test_from_script_invalid() {
        assert!(MigrationPayload::from_script(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn test_from_script_direct_push() {
        // Build a script with direct push (no OP_PUSHDATA1)
        let payload = MigrationPayload::new(&sample_pq_key(), &sample_proof(), 0);
        let encoded = payload.encode();
        let mut script = Vec::new();
        script.push(0x6a); // OP_RETURN
        script.push(PAYLOAD_SIZE as u8); // direct push length
        script.extend_from_slice(&encoded);
        assert!(MigrationPayload::is_migration_script(&script));
        let parsed = MigrationPayload::from_script(&script).unwrap();
        assert_eq!(payload, parsed);
    }

    // ----------------------------------------------------------
    //  from_hashes constructor
    // ----------------------------------------------------------

    #[test]
    fn test_from_hashes() {
        let pq_hash = [0x11; 32];
        let proof_hash = [0x22; 32];
        let payload =
            MigrationPayload::from_hashes(pq_hash, proof_hash, FLAG_PLONK, LEVEL_ML_DSA_65);
        assert_eq!(payload.pq_pubkey_hash, pq_hash);
        assert_eq!(payload.proof_hash, proof_hash);
        assert!(payload.is_plonk());
        assert_eq!(payload.level_name(), "ML-DSA-65");
    }

    // ----------------------------------------------------------
    //  Determinism
    // ----------------------------------------------------------

    #[test]
    fn test_encoding_deterministic() {
        let p1 = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_GROTH16);
        let p2 = MigrationPayload::new(&sample_pq_key(), &sample_proof(), FLAG_GROTH16);
        assert_eq!(p1.encode(), p2.encode());
    }

    #[test]
    fn test_different_keys_different_hashes() {
        let p1 = MigrationPayload::new(&vec![0xAA; 1952], &sample_proof(), 0);
        let p2 = MigrationPayload::new(&vec![0xBB; 1952], &sample_proof(), 0);
        assert_ne!(p1.pq_pubkey_hash, p2.pq_pubkey_hash);
        assert_eq!(p1.proof_hash, p2.proof_hash); // same proof
    }

    #[test]
    fn test_different_proofs_different_hashes() {
        let p1 = MigrationPayload::new(&sample_pq_key(), &vec![0xCC; 100], 0);
        let p2 = MigrationPayload::new(&sample_pq_key(), &vec![0xDD; 100], 0);
        assert_eq!(p1.pq_pubkey_hash, p2.pq_pubkey_hash); // same key
        assert_ne!(p1.proof_hash, p2.proof_hash);
    }
}
