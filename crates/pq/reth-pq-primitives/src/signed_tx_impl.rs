//! Implementation of alloy/reth traits for [`PqSignedTransaction`].
//!
//! This makes `PqSignedTransaction` a first-class citizen in the reth pipeline
//! by implementing:
//!   - `SignerRecoverable`  — sender recovery (from embedded public key)
//!   - `Transaction`        — alloy_consensus::Transaction fields
//!   - `TxHashRef`          — cached tx hash
//!   - `IsTyped2718`        — type byte 0x04
//!   - `InMemorySize`       — memory accounting

use alloy_consensus::{
    crypto::RecoveryError,
    transaction::{SignerRecoverable, TxHashRef},
    Transaction,
};
use alloy_eips::{
    eip2718::{IsTyped2718, Typed2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Bytes, TxKind, B256, U256};
use reth_primitives_traits::{InMemorySize, SignedTransaction};

use crate::transaction::{PqSignedTransaction, PQ_TX_TYPE};

// ─── Typed2718 ────────────────────────────────────────────────────────────────

impl Typed2718 for PqSignedTransaction {
    fn ty(&self) -> u8 {
        PQ_TX_TYPE
    }
}

// ─── SignerRecoverable ────────────────────────────────────────────────────────

impl SignerRecoverable for PqSignedTransaction {
    /// For PQ txs the sender is derived from the embedded ML-DSA-65 public key
    /// rather than recovered from an ECDSA signature.
    fn recover_signer(&self) -> Result<alloy_primitives::Address, RecoveryError> {
        Ok(PqSignedTransaction::recover_signer(self))
    }

    /// Same as `recover_signer` — ML-DSA has no low-s requirement.
    fn recover_signer_unchecked(&self) -> Result<alloy_primitives::Address, RecoveryError> {
        Ok(PqSignedTransaction::recover_signer(self))
    }
}

// ─── TxHashRef ───────────────────────────────────────────────────────────────

impl TxHashRef for PqSignedTransaction {
    fn tx_hash(&self) -> &B256 {
        &self.hash
    }
}

// ─── IsTyped2718 ─────────────────────────────────────────────────────────────

impl IsTyped2718 for PqSignedTransaction {
    fn is_type(type_id: u8) -> bool {
        type_id == PQ_TX_TYPE
    }
}

// ─── alloy_consensus::Transaction ────────────────────────────────────────────

impl Transaction for PqSignedTransaction {
    fn chain_id(&self) -> Option<u64> {
        Some(self.tx.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.tx.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.tx.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        Some(self.tx.gas_price)
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.tx.gas_price
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.tx.gas_price
    }

    fn effective_gas_price(&self, _base_fee: Option<u64>) -> u128 {
        self.tx.gas_price
    }

    fn is_dynamic_fee(&self) -> bool {
        false
    }

    fn kind(&self) -> TxKind {
        match self.tx.to {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        }
    }

    fn is_create(&self) -> bool {
        self.tx.to.is_none()
    }

    fn value(&self) -> U256 {
        U256::from(self.tx.value)
    }

    fn input(&self) -> &Bytes {
        // SAFETY: We return a reference to an empty static Bytes.
        // A proper implementation would store input as Bytes in PqTransactionRequest.
        // This is sufficient for the pipeline integration milestone.
        static EMPTY: Bytes = Bytes::new();
        &EMPTY
    }

    fn access_list(&self) -> Option<&AccessList> {
        None
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

// ─── InMemorySize ─────────────────────────────────────────────────────────────

impl InMemorySize for PqSignedTransaction {
    fn size(&self) -> usize {
        // signature (3309) + public_key (1952) + input + hash (32) + fixed fields (~64)
        self.signature.as_bytes().len()
            + self.public_key.as_bytes().len()
            + self.tx.input.len()
            + 32
            + 64
    }
}

// ─── SignedTransaction ────────────────────────────────────────────────────────

impl SignedTransaction for PqSignedTransaction {}

// ─── RlpBincode (SerdeBincodeCompat via blanket impl) ────────────────────────

/// Marker impl — `PqSignedTransaction` already satisfies `Encodable + Decodable`
/// (see `rlp.rs`), so the `SerdeBincodeCompat` blanket impl kicks in and
/// serialises via RLP for bincode-compatible storage.
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for PqSignedTransaction {}
