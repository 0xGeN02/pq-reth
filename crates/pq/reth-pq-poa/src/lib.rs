//! # reth-pq-poa
//!
//! Proof of Authority consensus engine for PostQuantumEVM.
//! Validators sign blocks with ML-DSA-65 in round-robin rotation.

pub mod engine;
pub mod sealer;
pub mod validator;

pub use engine::{PoaConfig, PoaEngine};
pub use sealer::{seal_header, verify_seal};
pub use validator::{Validator, ValidatorSet};
