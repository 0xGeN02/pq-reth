//! Bridge between [`PqSignedTransaction`] and revm's [`TxEnv`].
//!
//! Implements [`FromRecoveredTx`] and [`FromTxWithEncoded`] so that
//! `PqSignedTransaction` can be fed into the EVM execution pipeline.

use alloy_evm::{revm::context::TxEnv, FromRecoveredTx, FromTxWithEncoded};
use alloy_primitives::{Address, Bytes, TxKind, U256};

use crate::transaction::{PqSignedTransaction, PQ_TX_TYPE};

impl FromRecoveredTx<PqSignedTransaction> for TxEnv {
    fn from_recovered_tx(tx: &PqSignedTransaction, caller: Address) -> Self {
        Self {
            tx_type: PQ_TX_TYPE,
            caller,
            gas_limit: tx.tx.gas_limit,
            gas_price: tx.tx.gas_price,
            kind: match tx.tx.to {
                Some(addr) => TxKind::Call(addr),
                None => TxKind::Create,
            },
            value: U256::from(tx.tx.value),
            data: tx.tx.input.clone(),
            nonce: tx.tx.nonce,
            chain_id: Some(tx.tx.chain_id),
            ..Default::default()
        }
    }
}

impl FromTxWithEncoded<PqSignedTransaction> for TxEnv {
    fn from_encoded_tx(tx: &PqSignedTransaction, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}
