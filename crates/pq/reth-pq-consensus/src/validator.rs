//! Post-quantum transaction validator.
//!
//! [`PqTransactionValidator`] validates a [`PqSignedTransaction`]:
//! - Verifies the ML-DSA-65 signature.
//! - Checks chain ID, gas limit, gas price.
//! - Recovers and returns the sender address.

use alloy_primitives::Address;
use reth_pq_primitives::PqSignedTransaction;

use crate::error::PqConsensusError;

/// Validates post-quantum signed transactions.
///
/// Instantiate with the expected `chain_id` of the network.
#[derive(Debug, Clone)]
pub struct PqTransactionValidator {
    chain_id: u64,
}

impl PqTransactionValidator {
    /// Create a new validator for the given chain ID.
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id }
    }

    /// Validate a [`PqSignedTransaction`] and return the sender's `Address` on success.
    ///
    /// Checks performed (in order):
    /// 1. Chain ID matches.
    /// 2. Gas limit > 0.
    /// 3. Gas price > 0.
    /// 4. ML-DSA-65 signature is valid.
    pub fn validate(&self, tx: &PqSignedTransaction) -> Result<Address, PqConsensusError> {
        // 1. Chain ID
        if tx.tx.chain_id != self.chain_id {
            return Err(PqConsensusError::ChainIdMismatch {
                expected: self.chain_id,
                got: tx.tx.chain_id,
            });
        }

        // 2. Gas limit
        if tx.tx.gas_limit == 0 {
            return Err(PqConsensusError::ZeroGasLimit);
        }

        // 3. Gas price
        if tx.tx.gas_price == 0 {
            return Err(PqConsensusError::ZeroGasPrice);
        }

        // 4. ML-DSA-65 signature verification
        tx.verify()?;

        // 5. Recover sender
        Ok(tx.recover_signer())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use reth_pq_primitives::{PqSigner, PqTransactionRequest};

    use super::*;

    const CHAIN_ID: u64 = 1337;

    fn make_signed() -> PqSignedTransaction {
        let signer = PqSigner::generate();
        signer.sign_transaction(PqTransactionRequest {
            nonce: 1,
            to: Some(alloy_primitives::Address::from([0xde; 20])),
            value: 1_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            input: Bytes::new(),
            chain_id: CHAIN_ID,
        })
    }

    #[test]
    fn valid_transaction_passes() {
        let validator = PqTransactionValidator::new(CHAIN_ID);
        let signed = make_signed();
        let sender = validator.validate(&signed).expect("should validate");
        assert_eq!(sender, signed.recover_signer());
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let validator = PqTransactionValidator::new(999);
        let signed = make_signed();
        assert!(matches!(
            validator.validate(&signed),
            Err(PqConsensusError::ChainIdMismatch { expected: 999, got: CHAIN_ID })
        ));
    }

    #[test]
    fn zero_gas_limit_rejected() {
        let signer = PqSigner::generate();
        let signed = signer.sign_transaction(PqTransactionRequest {
            nonce: 1,
            to: None,
            value: 0,
            gas_limit: 0,
            gas_price: 1,
            input: Bytes::new(),
            chain_id: CHAIN_ID,
        });
        let validator = PqTransactionValidator::new(CHAIN_ID);
        assert!(matches!(validator.validate(&signed), Err(PqConsensusError::ZeroGasLimit)));
    }

    #[test]
    fn tampered_signature_rejected() {
        use reth_pq_primitives::PqSignature;

        let validator = PqTransactionValidator::new(CHAIN_ID);
        let mut signed = make_signed();
        // Corrupt the signature bytes
        let mut bad_bytes = signed.signature.as_bytes().to_vec();
        bad_bytes[0] ^= 0xFF;
        signed.signature = PqSignature::from_bytes(bad_bytes);
        assert!(validator.validate(&signed).is_err());
    }
}
