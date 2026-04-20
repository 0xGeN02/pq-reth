//! # reth-pq-consensus
//!
//! Post-quantum consensus validation for the `pq-reth` Ethereum client.
//!
//! Provides [`PqTransactionValidator`] — a standalone validator that checks
//! PQ-signed transactions (ML-DSA-65) independently of the classic ECDSA path.
//! This is designed to run **in addition** to the existing Ethereum consensus
//! checks, enabling a hybrid classical + post-quantum validation pipeline.
//!
//! ## Usage
//!
//! ```rust
//! use reth_pq_consensus::PqTransactionValidator;
//! use reth_pq_primitives::PqSigner;
//!
//! let signer = PqSigner::generate();
//! let tx = reth_pq_primitives::PqTransactionRequest {
//!     nonce: 0,
//!     to: None,
//!     value: 0,
//!     gas_limit: 21_000,
//!     gas_price: 1_000_000_000,
//!     input: vec![],
//!     chain_id: 1337,
//! };
//! let signed = signer.sign_transaction(tx);
//!
//! let validator = PqTransactionValidator::new(1337);
//! assert!(validator.validate(&signed).is_ok());
//! ```

pub mod error;
pub mod validator;

pub use error::PqConsensusError;
pub use validator::PqTransactionValidator;
