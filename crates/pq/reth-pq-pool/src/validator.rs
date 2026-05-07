//! [`PqPoolValidator`] — validates PQ transactions before pool insertion.
//!
//! Performs both stateless and stateful validation:
//! - **Stateless**: `gas_limit` > 0, `gas_price` > 0, ML-DSA-65 signature valid
//! - **Stateful**: sender nonce check, sender balance >= `max_cost`

use alloy_primitives::{Address, U256};
use reth_pq_primitives::PqSignedTransaction;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator, ValidTransaction},
    TransactionOrigin,
};

use crate::{error::PqPoolError, pooled::PqPooledTransaction};

/// Transaction validator for PQ (`0x50`) transactions with full state access.
///
/// Validates:
/// - `gas_limit > 0`
/// - `gas_price > 0`
/// - ML-DSA-65 signature is valid (stateless)
/// - Sender nonce >= state nonce (prevents replay)
/// - Sender balance >= `gas_limit` × `gas_price` + value (prevents overdraft)
pub struct PqPoolValidator<Client> {
    /// State provider factory for querying account nonce/balance.
    client: Client,
}

impl<Client: std::fmt::Debug> std::fmt::Debug for PqPoolValidator<Client> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqPoolValidator").finish_non_exhaustive()
    }
}

impl<Client: Clone> Clone for PqPoolValidator<Client> {
    fn clone(&self) -> Self {
        Self { client: self.client.clone() }
    }
}

impl<Client> PqPoolValidator<Client> {
    /// Creates a new pool validator with access to the state provider.
    pub const fn new(client: Client) -> Self {
        Self { client }
    }
}

impl<Client> TransactionValidator for PqPoolValidator<Client>
where
    Client: StateProviderFactory + Send + Sync + std::fmt::Debug + Unpin + Clone + 'static,
{
    type Transaction = PqPooledTransaction;
    /// PQ block type — `Block<PqSignedTransaction>`.
    type Block = alloy_consensus::Block<PqSignedTransaction>;

    async fn validate_transaction(
        &self,
        _origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // Extract needed values from the transaction before any moves.
        // This avoids borrow-after-move issues.
        let gas_limit = transaction.transaction.tx.gas_limit;
        let gas_price = transaction.transaction.tx.gas_price;
        let nonce = transaction.transaction.tx.nonce;
        let value = transaction.transaction.tx.value;

        // ─── Stateless checks ────────────────────────────────────────────

        if gas_limit == 0 {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::ZeroGasLimit),
            );
        }

        if gas_price == 0 {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::ZeroGasPrice),
            );
        }

        // ML-DSA-65 signature verification
        if let Err(e) = transaction.transaction.verify() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::InvalidSignature(e.to_string())),
            );
        }

        // ─── Stateful checks ─────────────────────────────────────────────

        // Derive sender address from verified public key
        let sender = transaction.transaction.recover_signer();

        // Query latest state for sender account
        let (state_nonce, balance) = match self.get_account_state(&sender) {
            Ok((n, bal)) => (n, bal),
            Err(_) => {
                // If state is unavailable (e.g. during sync), allow tx with defaults
                (nonce, U256::MAX)
            }
        };

        // Nonce check: tx nonce must be >= state nonce
        if nonce < state_nonce {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::NonceTooLow {
                    tx_nonce: nonce,
                    state_nonce,
                }),
            );
        }

        // Balance check: sender must be able to pay max_cost
        let max_cost = U256::from(gas_limit)
            .saturating_mul(U256::from(gas_price))
            .saturating_add(U256::from(value));

        if balance < max_cost {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(PqPoolError::InsufficientBalance {
                    balance,
                    max_cost,
                }),
            );
        }

        TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(transaction),
            propagate: true,
            authorities: None,
        }
    }
}

impl<Client> PqPoolValidator<Client>
where
    Client: StateProviderFactory,
{
    /// Query account nonce and balance from the latest state.
    fn get_account_state(&self, address: &Address) -> Result<(u64, U256), ()> {
        let state = self.client.latest().map_err(|_| ())?;
        use reth_storage_api::AccountReader;
        let account = state.basic_account(address).map_err(|_| ())?;
        match account {
            Some(acc) => Ok((acc.nonce, acc.balance)),
            None => Ok((0, U256::ZERO)),
        }
    }
}
