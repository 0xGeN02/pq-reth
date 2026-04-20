//! ML-DSA-65 signature and public-key wrapper types.
//!
//! These types provide byte-array serialisation and a clean API on top of the
//! raw `ml-dsa` types from `dilithium::dilithium65`.

use alloy_primitives::Address;
use dilithium::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::PqError;

// ─── PqPublicKey ─────────────────────────────────────────────────────────────

/// An ML-DSA-65 verifying (public) key — 1952 bytes.
///
/// The Ethereum `Address` is derived as the last 20 bytes of the Keccak-256
/// hash of the encoded key, matching the classical address derivation scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublicKey {
    /// Raw encoded verifying key bytes (1952 bytes for ML-DSA-65).
    bytes: Vec<u8>,
}

impl PqPublicKey {
    /// Wrap raw verifying-key bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive an Ethereum-style `Address` from this public key.
    ///
    /// Uses the same derivation as ECDSA: `Address = keccak256(pk_bytes)[12..]`.
    pub fn to_address(&self) -> Address {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(&self.bytes);
        Address::from_slice(&hash[12..])
    }

    /// Try to reconstruct the underlying `VerifyingKey<MlDsa65>`.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey<MlDsa65>, PqError> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(self.bytes.as_slice())
            .map_err(|_| PqError::InvalidPublicKey("wrong byte length".into()))?;
        Ok(VerifyingKey::decode(&encoded))
    }
}

// ─── PqSignature ─────────────────────────────────────────────────────────────

/// An ML-DSA-65 signature — 3309 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignature {
    /// Raw encoded signature bytes.
    bytes: Vec<u8>,
}

impl PqSignature {
    /// Wrap raw signature bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Try to reconstruct the underlying `Signature<MlDsa65>`.
    pub fn to_ml_dsa(&self) -> Result<Signature<MlDsa65>, PqError> {
        let encoded = EncodedSignature::<MlDsa65>::try_from(self.bytes.as_slice())
            .map_err(|_| PqError::InvalidSignatureBytes("wrong byte length".into()))?;
        Signature::<MlDsa65>::decode(&encoded)
            .ok_or_else(|| PqError::InvalidSignatureBytes("decode failed".into()))
    }
}

/// Verify a [`PqSignature`] over `msg` using the given [`PqPublicKey`].
pub fn verify(pk: &PqPublicKey, msg: &[u8], sig: &PqSignature) -> Result<(), PqError> {
    let vk = pk.to_verifying_key()?;
    let ml_sig = sig.to_ml_dsa()?;
    dilithium::dilithium65::verify(&vk, msg, &ml_sig).map_err(|_| PqError::InvalidSignature)
}
