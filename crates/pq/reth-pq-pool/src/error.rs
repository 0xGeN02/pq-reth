//! Error types for PQ pool operations.

use reth_transaction_pool::error::PoolTransactionError;
use std::any::Any;
use thiserror::Error;

/// Errors that can occur during PQ pool validation or conversion.
#[derive(Debug, Error)]
pub enum PqPoolError {
    /// The transaction type is not 0x04.
    #[error("not a PQ transaction (expected type 0x04, got {0:#x})")]
    WrongType(u8),

    /// The transaction is missing the embedded public key.
    #[error("PQ transaction missing embedded public key")]
    MissingPublicKey,

    /// The ML-DSA-65 signature is invalid.
    #[error("invalid ML-DSA-65 signature: {0}")]
    InvalidSignature(String),

    /// Gas limit is zero.
    #[error("gas_limit must be greater than 0")]
    ZeroGasLimit,

    /// Gas price is zero.
    #[error("gas_price must be greater than 0")]
    ZeroGasPrice,
}

impl PoolTransactionError for PqPoolError {
    fn is_bad_transaction(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
