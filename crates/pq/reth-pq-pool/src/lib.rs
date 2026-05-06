//! # reth-pq-pool
//!
//! Post-quantum transaction pool integration for pq-reth.
//!
//! Implements [`PoolTransaction`] for [`PqSignedTransaction`] so that PQ
//! transactions of type `0x50` can enter, be ordered and be included in blocks
//! via the standard reth transaction pool infrastructure.
//!
//! ## State Access
//!
//! [`PqPoolValidator`] queries the latest chain state for nonce/balance
//! validation, preventing nonce replay and insufficient balance transactions
//! from entering the pool.

pub mod error;
pub mod pooled;
pub mod validator;

pub use pooled::PqPooledTransaction;
pub use validator::PqPoolValidator;
