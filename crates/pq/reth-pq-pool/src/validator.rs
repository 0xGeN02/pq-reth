//! [`PqPoolValidator`] — validates PQ transactions before pool insertion.

use alloy_primitives::U256;
use reth_pq_primitives::PqSignedTransaction;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator, ValidTransaction},
    TransactionOrigin,
};

use crate::{error::PqPoolError, pooled::PqPooledTransaction};

/// A minimal transaction validator for PQ (`0x04`) transactions.
///
/// Checks:
/// - `gas_limit > 0`
/// - `gas_price > 0`
/// - ML-DSA-65 signature is valid
///
/// Note: A production validator would also query state for real balance and
/// nonce values. This implementation reports `balance = U256::MAX` and the
/// transaction's own `nonce` as the state nonce, which is sufficient for
/// testing the pool integration.
#[derive(Debug, Clone)]
pub struct PqPoolValidator;

impl TransactionValidator for PqPoolValidator {
    type Transaction = PqPooledTransaction;
    /// Standard Ethereum block type — we don't use block context here.
    type Block = reth_ethereum_primitives::Block;

    async fn validate_transaction(
        &self,
        _origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let tx: &PqSignedTransaction = &*transaction.transaction;

        // gas_limit must be > 0
        if tx.tx.gas_limit == 0 {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::ZeroGasLimit),
            );
        }

        // gas_price must be > 0
        if tx.tx.gas_price == 0 {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::ZeroGasPrice),
            );
        }

        // ML-DSA-65 signature verification
        if let Err(e) = tx.verify() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::InvalidSignature(e.to_string())),
            );
        }

        TransactionValidationOutcome::Valid {
            balance: U256::MAX,
            state_nonce: tx.tx.nonce,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(transaction),
            propagate: true,
            authorities: None,
        }
    }
}
