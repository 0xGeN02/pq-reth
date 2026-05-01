//! Block sealing: sign and verify block headers with ML-DSA-65.

use dilithium::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey,
    dilithium65,
};
use dilithium::signature::SignatureEncoding;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use thiserror::Error;

/// Errors during seal operations.
#[derive(Debug, Error)]
pub enum SealError {
    /// The seal has an invalid length (expected 3309 bytes for ML-DSA-65).
    #[error("invalid seal length: expected 3309 bytes, got {0}")]
    InvalidLength(usize),

    /// The ML-DSA-65 signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// The verifying key bytes could not be decoded.
    #[error("verifying key decode failed")]
    InvalidPublicKey,
}

/// Compute the seal hash of a block header (SHAKE-256 of the header fields).
/// In production this would RLP-encode the header without the seal field.
/// For now, we hash the raw header bytes passed in.
pub fn header_hash(header_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(header_bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

/// Seal a block header: sign its hash with the validator's ML-DSA-65 key.
/// Returns the 3309-byte signature.
pub fn seal_header(sk: &SigningKey<MlDsa65>, header_bytes: &[u8]) -> Vec<u8> {
    let hash = header_hash(header_bytes);
    let sig = dilithium65::sign(sk, &hash);
    sig.to_bytes().to_vec()
}

/// Verify a block seal against the expected validator's public key.
pub fn verify_seal(pk_bytes: &[u8], header_bytes: &[u8], seal: &[u8]) -> Result<(), SealError> {
    // Check seal length (ML-DSA-65 signature = 3309 bytes)
    if seal.len() != 3309 {
        return Err(SealError::InvalidLength(seal.len()));
    }

    // Decode the verifying key
    let encoded_pk = EncodedVerifyingKey::<MlDsa65>::try_from(pk_bytes)
        .map_err(|_| SealError::InvalidPublicKey)?;
    let pk = VerifyingKey::<MlDsa65>::decode(&encoded_pk);

    // Decode the signature
    let encoded_sig = EncodedSignature::<MlDsa65>::try_from(seal)
        .map_err(|_| SealError::InvalidSignature)?;
    let sig = Signature::<MlDsa65>::decode(&encoded_sig)
        .ok_or(SealError::InvalidSignature)?;

    // Compute header hash and verify
    let hash = header_hash(header_bytes);
    dilithium65::verify(&pk, &hash, &sig).map_err(|_| SealError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dilithium::signature::Keypair;

    #[test]
    fn seal_and_verify_roundtrip() {
        let sk = dilithium65::keygen();
        let vk = sk.verifying_key();
        let header = b"block header content for testing";

        let seal = seal_header(&sk, header);
        assert_eq!(seal.len(), 3309);

        let vk_bytes = vk.encode();
        verify_seal(vk_bytes.as_slice(), header, &seal).expect("valid seal must verify");
    }

    #[test]
    fn tampered_header_fails() {
        let sk = dilithium65::keygen();
        let vk = sk.verifying_key();
        let header = b"original header";
        let tampered = b"tampered header";

        let seal = seal_header(&sk, header);
        let vk_bytes = vk.encode();

        let result = verify_seal(vk_bytes.as_slice(), tampered, &seal);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk1 = dilithium65::keygen();
        let sk2 = dilithium65::keygen();
        let header = b"some header";

        let seal = seal_header(&sk1, header);
        let wrong_vk_bytes = sk2.verifying_key().encode();

        let result = verify_seal(wrong_vk_bytes.as_slice(), header, &seal);
        assert!(result.is_err());
    }
}
