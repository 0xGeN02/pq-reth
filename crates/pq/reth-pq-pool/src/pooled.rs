//! [`PqPooledTransaction`] — the pooled representation of a PQ transaction.
//!
//! This wraps a [`Recovered<PqSignedTransaction>`] (tx + sender address) and
//! pre-computes the fields the pool needs for ordering: cost, encoded length.

use alloy_consensus::{transaction::Recovered, Transaction};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718},
    eip4844::{env_settings::KzgSettings, BlobTransactionValidationError},
    eip7594::BlobTransactionSidecarVariant,
};
use alloy_primitives::{Address, B256, U256};
use reth_pq_primitives::{PqSignedTransaction, PQ_TX_TYPE};
use reth_primitives_traits::InMemorySize;
use reth_transaction_pool::{EthBlobTransactionSidecar, EthPoolTransaction, PoolTransaction};
use std::{convert::Infallible, fmt, sync::Arc};

use crate::error::PqPoolError;

// ─── PqPooledTransaction ─────────────────────────────────────────────────────

/// A post-quantum transaction in the pool.
///
/// Wraps a [`Recovered<PqSignedTransaction>`] and caches the pre-computed
/// fields required for ordering.
#[derive(Debug, Clone)]
pub struct PqPooledTransaction {
    /// The signed transaction with its recovered sender.
    pub transaction: Recovered<PqSignedTransaction>,
    /// Pre-computed maximum cost: `gas_price * gas_limit + value`.
    pub cost: U256,
    /// Pre-computed EIP-2718 encoded length.
    pub encoded_length: usize,
}

impl PqPooledTransaction {
    /// Construct from a recovered transaction, pre-computing cost and length.
    pub fn new(transaction: Recovered<PqSignedTransaction>) -> Self {
        let cost = Self::compute_cost(&transaction);
        let encoded_length = transaction.encode_2718_len();
        Self { transaction, cost, encoded_length }
    }

    fn compute_cost(tx: &Recovered<PqSignedTransaction>) -> U256 {
        let gas_cost =
            U256::from(tx.gas_price().unwrap_or(0)).saturating_mul(U256::from(tx.gas_limit()));
        gas_cost.saturating_add(tx.value())
    }
}

// ─── PoolTransaction ─────────────────────────────────────────────────────────

impl PoolTransaction for PqPooledTransaction {
    /// Consensus → Pooled conversion is infallible since they're the same type.
    type TryFromConsensusError = Infallible;
    /// Consensus and pooled types are the same for PQ — no blob sidecar.
    type Consensus = PqSignedTransaction;
    type Pooled = PqSignedTransaction;

    fn try_from_consensus(
        tx: Recovered<Self::Consensus>,
    ) -> Result<Self, Self::TryFromConsensusError> {
        Ok(Self::new(tx))
    }

    fn consensus_ref(&self) -> Recovered<&Self::Consensus> {
        Recovered::new_unchecked(&*self.transaction, self.transaction.signer())
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.transaction
    }

    fn from_pooled(pooled: Recovered<Self::Pooled>) -> Self {
        Self::new(pooled)
    }

    fn hash(&self) -> &B256 {
        use alloy_consensus::transaction::TxHashRef;
        self.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        *self.transaction.signer_ref()
    }

    fn sender_ref(&self) -> &Address {
        self.transaction.signer_ref()
    }

    fn cost(&self) -> &U256 {
        &self.cost
    }

    fn encoded_length(&self) -> usize {
        self.encoded_length
    }
}

// ─── EthPoolTransaction ───────────────────────────────────────────────────────
// PQ transactions have no blob sidecars, but we must satisfy the trait.

impl EthPoolTransaction for PqPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        // PQ transactions are never EIP-4844
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _blob: &BlobTransactionSidecarVariant,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Ok(())
    }
}

// ─── Delegation of alloy_consensus::Transaction ──────────────────────────────

impl alloy_consensus::Transaction for PqPooledTransaction {
    fn chain_id(&self) -> Option<u64> {
        self.transaction.chain_id()
    }
    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }
    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }
    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }
    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }
    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }
    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }
    fn is_dynamic_fee(&self) -> bool {
        false
    }
    fn kind(&self) -> alloy_primitives::TxKind {
        self.transaction.kind()
    }
    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }
    fn value(&self) -> U256 {
        self.transaction.value()
    }
    fn input(&self) -> &alloy_primitives::Bytes {
        self.transaction.input()
    }
    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        None
    }
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }
    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

impl alloy_eips::eip2718::Typed2718 for PqPooledTransaction {
    fn ty(&self) -> u8 {
        PQ_TX_TYPE
    }
}

impl InMemorySize for PqPooledTransaction {
    fn size(&self) -> usize {
        self.transaction.size()
    }
}

impl fmt::Display for PqPooledTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPooledTransaction {{ hash: {}, sender: {} }}", self.hash(), self.sender())
    }
}
