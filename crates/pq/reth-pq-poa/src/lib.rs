//! # reth-pq-poa
//!
//! Proof of Authority consensus engine for PostQuantumEVM.
//! Validators sign blocks with ML-DSA-65 in round-robin rotation.
//!
//! ## Integration with reth
//!
//! - [`mining::PoaMiningStream`] integrates with reth's `MiningMode::Trigger`
//!   to drive block production only when this node is the authorized proposer.
//! - [`consensus::PqPoaConsensus`] wraps standard consensus with ML-DSA-65
//!   seal verification on incoming blocks.

pub mod consensus;
pub mod engine;
pub mod mining;
pub mod sealer;
pub mod validator;

pub use consensus::PqPoaConsensus;
pub use engine::{PoaConfig, PoaEngine};
pub use mining::PoaMiningStream;
pub use sealer::{seal_header, verify_seal};
pub use validator::{Validator, ValidatorSet};
