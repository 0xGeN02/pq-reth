//! Consensus error types for post-quantum validation.

use thiserror::Error;

/// Errors produced by PQ transaction validation.
#[derive(Debug, Error)]
pub enum PqConsensusError {
    /// The ML-DSA-65 signature is invalid.
    #[error("invalid PQ signature: {0}")]
    InvalidSignature(#[from] reth_pq_primitives::PqError),

    /// The transaction chain ID does not match the expected chain ID.
    #[error("chain ID mismatch: expected {expected}, got {got}")]
    ChainIdMismatch {
        /// Expected chain ID.
        expected: u64,
        /// Actual chain ID from the transaction.
        got: u64,
    },

    /// The nonce is zero but the transaction was expected to have a higher nonce.
    #[error("nonce overflow")]
    NonceOverflow,

    /// Gas limit is zero.
    #[error("gas limit must be greater than zero")]
    ZeroGasLimit,

    /// Gas price is zero (considered invalid in most contexts).
    #[error("gas price must be greater than zero")]
    ZeroGasPrice,

    /// The transaction type byte is not `PQ_TX_TYPE` (0x04).
    #[error("not a PQ transaction (expected type 0x04)")]
    WrongTransactionType,
}
