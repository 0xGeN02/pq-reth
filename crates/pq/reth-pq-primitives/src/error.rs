//! Error types for post-quantum primitives.

use thiserror::Error;

/// Errors produced by post-quantum cryptographic operations.
#[derive(Debug, Error)]
pub enum PqError {
    /// ML-DSA signature verification failed.
    #[error("PQ signature verification failed")]
    InvalidSignature,

    /// The public key bytes are malformed or have the wrong length.
    #[error("invalid PQ public key: {0}")]
    InvalidPublicKey(String),

    /// The signature bytes are malformed or have the wrong length.
    #[error("invalid PQ signature bytes: {0}")]
    InvalidSignatureBytes(String),

    /// Transaction hash could not be computed.
    #[error("transaction hash error: {0}")]
    HashError(String),
}
