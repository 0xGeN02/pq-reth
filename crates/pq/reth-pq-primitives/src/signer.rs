//! High-level signer abstraction for post-quantum transactions.
//!
//! [`PqSigner`] holds an ML-DSA-65 signing key and provides methods to sign
//! [`PqTransactionRequest`]s and derive the Ethereum address.

use alloy_primitives::Address;
use dilithium::{
    signature::{Keypair, Signer},
    MlDsa65, SigningKey,
};

use crate::{
    transaction::{PqSignedTransaction, PqTransactionRequest},
    PqPublicKey, PqSignature,
};

/// A post-quantum signer backed by an ML-DSA-65 signing key.
#[derive(Debug)]
pub struct PqSigner {
    sk: SigningKey<MlDsa65>,
}

impl PqSigner {
    /// Generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Self {
        Self { sk: dilithium::dilithium65::keygen() }
    }

    /// The Ethereum address derived from this signer's public key.
    pub fn address(&self) -> Address {
        self.public_key().to_address()
    }

    /// The ML-DSA-65 public key of this signer.
    pub fn public_key(&self) -> PqPublicKey {
        let vk = self.sk.verifying_key();
        let encoded = vk.encode();
        PqPublicKey::from_bytes(encoded.as_slice().to_vec())
    }

    /// Sign a [`PqTransactionRequest`], producing a [`PqSignedTransaction`].
    pub fn sign_transaction(&self, tx: PqTransactionRequest) -> PqSignedTransaction {
        let hash = tx.signing_hash();
        let sig = self.sk.sign(hash.as_slice());
        let sig_bytes = sig.encode().as_slice().to_vec();

        PqSignedTransaction::new(tx, PqSignature::from_bytes(sig_bytes), self.public_key())
    }
}
