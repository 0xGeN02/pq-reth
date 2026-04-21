//! # reth-pq-primitives
//!
//! Post-quantum cryptographic primitives for the `pq-reth` Ethereum client.
//!
//! Replaces ECDSA / secp256k1 with **ML-DSA-65** (CRYSTALS-Dilithium, NIST FIPS 204)
//! for transaction signing and verification.
//!
//! ## Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`PqPublicKey`]        | ML-DSA-65 verifying (public) key — 1952 bytes |
//! | [`PqSignature`]        | ML-DSA-65 signature — 3309 bytes |
//! | [`PqTransactionRequest`] | Unsigned PQ transaction fields |
//! | [`PqSignedTransaction`]  | Signed PQ transaction with recovery support |
//!
//! ## Usage
//!
//! ```rust
//! use reth_pq_primitives::{PqSigner, PqSignedTransaction, PqTransactionRequest};
//! use alloy_primitives::Bytes;
//!
//! let signer = PqSigner::generate();
//! let tx = PqTransactionRequest {
//!     nonce: 0,
//!     to: None,
//!     value: 1_000_000_000_000_000_000u128, // 1 ETH in wei
//!     gas_limit: 21_000,
//!     gas_price: 1_000_000_000,
//!     input: Bytes::new(),
//!     chain_id: 1337,
//! };
//! let signed = signer.sign_transaction(tx);
//! assert!(signed.verify().is_ok());
//! ```

pub mod compact;
pub mod error;
pub mod rlp;
pub mod signature;
pub mod signed_tx_impl;
pub mod signer;
pub mod transaction;
pub mod tx_env;

pub use error::PqError;
pub use signature::{PqPublicKey, PqSignature};
pub use signer::PqSigner;
pub use transaction::{PqSignedTransaction, PqTransactionRequest, PqTxType, PQ_TX_TYPE};
