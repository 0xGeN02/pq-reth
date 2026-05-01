//! Validator set management and slot assignment for PoA consensus.

use serde::{Deserialize, Serialize};

/// A single PoA validator, identified by its address. Uses ML-DSA-65 public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Ethereum-like address (20 bytes); derived from shake256(pk)[12..]
    pub address: [u8; 20],
    /// ML-DSA-65 verifying key (1952 bytes)
    pub public_key: Vec<u8>,
}

/// The set of authorized validators for the PoA chain.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// The list of validators currently authorized to produce blocks.
    validators: Vec<Validator>,
}

impl ValidatorSet {
    /// Create a new validator set from a list of validators.
    /// Panics if the list is empty.
    pub fn new(validators: Vec<Validator>) -> Self {
        assert!(!validators.is_empty(), "Validator set cannot be empty");
        Self { validators }
    }

    /// Number of validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns true if the validator set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Determine which validator should propose at a given block number.
    /// Uses simple round-robin: proposer = block_number % num_validators.
    pub fn proposer_at(&self, block_number: u64) -> &Validator {
        let index = (block_number as usize) % self.validators.len();
        &self.validators[index]
    }

    /// Check if a given address is the expected proposer for a block number.
    pub fn is_proposer(&self, block_number: u64, address: &[u8; 20]) -> bool {
        self.proposer_at(block_number).address == *address
    }

    /// Get a validator by address, if it exists in the set.
    pub fn get_by_address(&self, address: &[u8; 20]) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }
}
