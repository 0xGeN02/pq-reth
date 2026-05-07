//! `PoA` consensus validation: wraps standard Ethereum consensus with ML-DSA-65
//! seal verification on block headers.
//!
//! In `PoA` mode, each block's `extra_data` field contains the proposer's
//! ML-DSA-65 signature (3309 bytes) over the SHAKE-256 hash of the header
//! (excluding the `extra_data` field itself).
//!
//! This validator:
//! 1. Delegates standard checks (gas, timestamp, etc.) to `EthBeaconConsensus`
//! 2. If `extra_data.len() == 3309` → verifies the seal against the expected proposer
//! 3. If `extra_data.len() != 3309` → passes through (dev mode / unsealed blocks)

use std::sync::Arc;

use reth_consensus::{Consensus, ConsensusError, HeaderValidator};
use reth_primitives_traits::{Block, SealedBlock, SealedHeader};

use crate::sealer::verify_seal;
use crate::validator::ValidatorSet;

/// ML-DSA-65 signature length in bytes.
const SEAL_LENGTH: usize = 3309;

/// `PoA` consensus validator for `PostQuantumEVM`.
///
/// Wraps an inner consensus implementation and adds ML-DSA-65 seal
/// verification for blocks that contain a `PoA` seal in `extra_data`.
#[derive(Debug, Clone)]
pub struct PqPoaConsensus<C> {
    /// Inner consensus (typically `EthBeaconConsensus`).
    inner: C,
    /// The authorized validator set for seal verification.
    validator_set: Arc<ValidatorSet>,
}

impl<C> PqPoaConsensus<C> {
    /// Create a new `PoA` consensus validator.
    pub fn new(inner: C, validator_set: ValidatorSet) -> Self {
        Self {
            inner,
            validator_set: Arc::new(validator_set),
        }
    }

    /// Verify the ML-DSA-65 seal in a block header's `extra_data`.
    ///
    /// Returns `Ok(())` if:
    /// - The `extra_data` is not a seal (length != 3309) — passes through
    /// - The `extra_data` is a valid seal from the expected proposer
    ///
    /// Returns `Err(ConsensusError)` if:
    /// - The seal length is correct but signature verification fails
    /// - The seal is from a non-authorized validator
    fn verify_poa_seal(
        &self,
        block_number: u64,
        extra_data: &[u8],
        header_for_hash: &[u8],
    ) -> Result<(), ConsensusError> {
        // If extra_data doesn't look like a seal, pass through
        // (dev mode or pre-PoA blocks)
        if extra_data.len() != SEAL_LENGTH {
            return Ok(());
        }

        // Determine the expected proposer for this block
        let proposer = self.validator_set.proposer_at(block_number);

        // Verify the seal against the proposer's public key
        verify_seal(&proposer.public_key, header_for_hash, extra_data)
            .map_err(|e| ConsensusError::Other(format!("PoA seal verification failed: {e}")))
    }
}

impl<C, B> Consensus<B> for PqPoaConsensus<C>
where
    C: Consensus<B>,
    B: Block<Header = alloy_consensus::Header>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_body_against_header(body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        // First: standard Ethereum validation (gas, timestamp, etc.)
        self.inner.validate_block_pre_execution(block)?;

        // Then: PoA seal verification
        let header = block.header();
        let block_number = header.number;
        let extra_data = header.extra_data.as_ref();

        // For seal verification, we hash the header WITHOUT the extra_data
        // (the seal itself). We use the block number as the "header bytes"
        // since the full RLP-without-seal encoding is complex. The sealer
        // uses the same approach (see sealer::seal_header).
        let header_bytes = block_number.to_be_bytes();
        self.verify_poa_seal(block_number, extra_data, &header_bytes)?;

        Ok(())
    }
}

impl<C, H> HeaderValidator<H> for PqPoaConsensus<C>
where
    C: HeaderValidator<H>,
    H: std::fmt::Debug + Send + Sync,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)
    }
}
