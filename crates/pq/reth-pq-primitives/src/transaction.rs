//! Post-quantum transaction types.
//!
//! [`PqTransactionRequest`] — unsigned transaction fields.
//! [`PqSignedTransaction`]  — transaction + ML-DSA-65 signature + public key.

use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    signature::{verify, PqPublicKey, PqSignature},
    PqError,
};

/// EIP-2718 transaction type identifier for PQ transactions.
///
/// `0x04` — chosen to avoid collision with existing types:
///   - 0x00 Legacy
///   - 0x01 EIP-2930
///   - 0x02 EIP-1559
///   - 0x03 EIP-4844
pub const PQ_TX_TYPE: u8 = 0x04;

// ─── PqTxType ────────────────────────────────────────────────────────────────

/// Transaction type marker for PQ transactions.
///
/// A unit struct implementing `Typed2718`, used as
/// `<PqSignedTransaction as TransactionEnvelope>::TxType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PqTxType;

// ─── PqTransactionRequest ────────────────────────────────────────────────────

/// The unsigned fields of a post-quantum transaction.
///
/// Structurally equivalent to an EIP-1559 transaction but with `chain_id`
/// mandatory (replay protection) and the signature replaced by ML-DSA-65.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PqTransactionRequest {
    /// Sender nonce — prevents replay attacks.
    pub nonce: u64,
    /// Recipient address. `None` for contract creation.
    pub to: Option<Address>,
    /// Value transferred in wei.
    pub value: u128,
    /// Maximum gas units the transaction may consume.
    pub gas_limit: u64,
    /// Gas price in wei per gas unit.
    pub gas_price: u128,
    /// Transaction input data (calldata or init code).
    pub input: Bytes,
    /// Chain ID — mandatory for replay protection.
    pub chain_id: u64,
}

impl PqTransactionRequest {
    /// Compute the signing hash: `keccak256(type || rlp_encode(fields))`.
    ///
    /// For simplicity we use a canonical SSZ-like encoding rather than full
    /// RLP; a production implementation would use `alloy-rlp`.
    pub fn signing_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update([PQ_TX_TYPE]);
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.gas_price.to_be_bytes());
        hasher.update(self.gas_limit.to_be_bytes());
        match self.to {
            Some(ref addr) => {
                hasher.update([1u8]);
                hasher.update(addr.as_slice());
            }
            None => hasher.update([0u8]),
        }
        hasher.update(self.value.to_be_bytes());
        hasher.update(&self.input);
        B256::from_slice(&hasher.finalize())
    }
}

// ─── PqSignedTransaction ─────────────────────────────────────────────────────

/// A post-quantum signed transaction.
///
/// Contains the original unsigned fields, the ML-DSA-65 signature, and the
/// signer's public key (needed for sender recovery, since ML-DSA signatures
/// are not recoverable like ECDSA).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PqSignedTransaction {
    /// Unsigned transaction request.
    pub tx: PqTransactionRequest,
    /// ML-DSA-65 signature over `tx.signing_hash()`.
    pub signature: PqSignature,
    /// Signer's ML-DSA-65 public key.
    pub public_key: PqPublicKey,
    /// Cached transaction hash (keccak256 of the full signed encoding).
    pub hash: B256,
}

impl PqSignedTransaction {
    /// Construct a `PqSignedTransaction` from its parts.
    ///
    /// Computes and caches the transaction hash.
    pub fn new(tx: PqTransactionRequest, signature: PqSignature, public_key: PqPublicKey) -> Self {
        let hash = Self::compute_hash(&tx, &signature, &public_key);
        Self { tx, signature, public_key, hash }
    }

    /// The transaction hash — `keccak256(type || signing_hash || sig_bytes || pk_bytes)`.
    pub fn hash(&self) -> B256 {
        self.hash
    }

    /// Recover (derive) the sender address from the embedded public key.
    ///
    /// Unlike ECDSA, ML-DSA signatures are not recoverable — the public key
    /// must be included in the transaction explicitly.
    pub fn recover_signer(&self) -> Address {
        self.public_key.to_address()
    }

    /// Verify the ML-DSA-65 signature against the transaction signing hash.
    pub fn verify(&self) -> Result<(), PqError> {
        let hash = self.tx.signing_hash();
        verify(&self.public_key, hash.as_slice(), &self.signature)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn compute_hash(tx: &PqTransactionRequest, sig: &PqSignature, pk: &PqPublicKey) -> B256 {
        let signing_hash = tx.signing_hash();
        let mut hasher = Keccak256::new();
        hasher.update([PQ_TX_TYPE]);
        hasher.update(signing_hash.as_slice());
        hasher.update(sig.as_bytes());
        hasher.update(pk.as_bytes());
        B256::from_slice(&hasher.finalize())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PqSigner;

    fn make_tx() -> PqTransactionRequest {
        PqTransactionRequest {
            nonce: 42,
            to: Some(Address::from([0xab; 20])),
            value: 1_000_000_000_000_000_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            input: Bytes::new(),
            chain_id: 1337,
        }
    }

    #[test]
    fn signing_hash_is_deterministic() {
        let tx = make_tx();
        assert_eq!(tx.signing_hash(), tx.signing_hash());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = PqSigner::generate();
        let signed = signer.sign_transaction(make_tx());
        assert!(signed.verify().is_ok(), "valid signature should verify");
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let signer1 = PqSigner::generate();
        let signer2 = PqSigner::generate();

        let mut signed = signer1.sign_transaction(make_tx());
        // Swap the public key — verification must fail
        signed.public_key = signer2.public_key();

        assert!(signed.verify().is_err(), "verification must fail with wrong public key");
    }

    #[test]
    fn recover_signer_matches_key_address() {
        let signer = PqSigner::generate();
        let signed = signer.sign_transaction(make_tx());
        assert_eq!(signed.recover_signer(), signer.address());
    }

    #[test]
    fn tx_type_is_0x04() {
        assert_eq!(PQ_TX_TYPE, 0x04);
    }
}
