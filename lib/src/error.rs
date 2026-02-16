//! Error types for the PQ Bitcoin SDK.

use core::fmt;

/// Errors that can occur in PQ Bitcoin operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PQBitcoinError {
    /// Public key has an invalid length for the expected format.
    InvalidKeyLength {
        /// Description of which key was invalid.
        context: &'static str,
        /// The expected length in bytes.
        expected: usize,
        /// The actual length in bytes.
        actual: usize,
    },
    /// PQ public key size doesn't match any known ML-DSA level.
    InvalidPQKeySize {
        /// The actual size provided.
        actual: usize,
    },
    /// A hash or digest operation failed.
    HashError(String),
    /// A secp256k1 operation failed.
    Secp256k1Error(String),
}

impl fmt::Display for PQBitcoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength {
                context,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{context}: expected {expected} bytes, got {actual} bytes"
                )
            }
            Self::InvalidPQKeySize { actual } => {
                write!(
                    f,
                    "invalid PQ public key size: {actual} bytes (expected 1312, 1952, or 2592)"
                )
            }
            Self::HashError(msg) => write!(f, "hash error: {msg}"),
            Self::Secp256k1Error(msg) => write!(f, "secp256k1 error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PQBitcoinError {}
