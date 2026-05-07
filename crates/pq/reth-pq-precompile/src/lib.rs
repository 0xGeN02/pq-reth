//! # reth-pq-precompile
//!
//! ML-DSA-65 signature verification precompile at address `0x0100`.
//!
//! ## Interface
//!
//! **Address:** `0x0000000000000000000000000000000000000100`
//!
//! Addresses `0x01`–`0x13` are used by built-in Ethereum precompiles (ecrecover,
//! sha256, ripemd160, identity, modexp, bn254, blake2f, kzg, BLS12-381). We use
//! `0x0100` (256) to avoid any collision with current or near-future EIPs.
//!
//! **Input layout (concatenation):**
//! ```text
//! [ msg_hash  : 32  bytes ]  SHAKE-256 hash of the signed message
//! [ signature : 3309 bytes]  ML-DSA-65 raw signature
//! [ public_key: 1952 bytes]  ML-DSA-65 raw verifying key
//! Total input: 5293 bytes
//! ```
//!
//! **Output (32 bytes, ABI-compatible uint256):**
//! ```text
//! 0x0000...0001  — valid signature   (uint256(1))
//! 0x0000...0000  — invalid signature (uint256(0))
//! ```
//!
//! The 32-byte output is left-padded for direct use with `abi.decode(result, (uint256))`
//! or `abi.decode(result, (bool))` in Solidity, matching the convention used by
//! ecrecover and other precompiles.
//!
//! **Gas cost:** 50 000 (static). This reflects the ~0.04s verification time of
//! ML-DSA-65 vs ~3 000 gas for `ecrecover`. Adjust once benchmarks are available.
//!
//! ## Usage from Solidity
//!
//! ```solidity
//! function pqVerify(
//!     bytes32 msgHash,
//!     bytes calldata signature,   // 3309 bytes
//!     bytes calldata publicKey    // 1952 bytes
//! ) internal view returns (bool) {
//!     bytes memory input = abi.encodePacked(msgHash, signature, publicKey);
//!     (bool ok, bytes memory result) = address(0x0100).staticcall(input);
//!     return ok && result.length == 32 && uint256(bytes32(result)) == 1;
//! }
//! ```

use alloy_primitives::{address, Address, Bytes};
use revm_precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Address of the ML-DSA-65 verify precompile (0x0100).
///
/// Chosen above 0x11 (last BLS12-381 precompile) to avoid collision with
/// any current or planned Ethereum built-in precompile.
pub const MLDSA_VERIFY_ADDRESS: Address = address!("0000000000000000000000000000000000000100");

/// Static gas cost for one ML-DSA-65 verification.
///
/// Calibrated from benchmarks: ML-DSA-65 verify takes ~42µs vs ecrecover at ~49µs.
/// Using ecrecover's rate of 61 gas/µs: 42 × 61 = 2,562, plus 20% safety margin.
/// See `docs/GAS_COST_ANALYSIS.md` for full derivation.
pub const MLDSA_VERIFY_GAS: u64 = 3_450;

/// Expected input length: hash (32) + signature (3309) + `public_key` (1952).
pub const INPUT_LEN: usize = 32 + 3309 + 1952;

/// 32-byte output for valid signature: uint256(1).
const OUTPUT_VALID: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};

/// 32-byte output for invalid signature: uint256(0).
const OUTPUT_INVALID: [u8; 32] = [0u8; 32];

// ─── Precompile function ─────────────────────────────────────────────────────

/// ML-DSA-65 signature verification precompile.
///
/// Signature: `fn(&[u8], u64) -> PrecompileResult`
pub fn ml_dsa_verify(input: &[u8], gas_limit: u64) -> PrecompileResult {
    // ── Gas check ────────────────────────────────────────────────────────────
    if gas_limit < MLDSA_VERIFY_GAS {
        return Err(PrecompileError::OutOfGas);
    }

    // ── Input validation ─────────────────────────────────────────────────────
    if input.len() != INPUT_LEN {
        // Wrong length — return uint256(0) (invalid), don't revert
        return Ok(PrecompileOutput::new(MLDSA_VERIFY_GAS, Bytes::copy_from_slice(&OUTPUT_INVALID)));
    }

    let msg_hash = &input[..32];
    let sig_bytes = &input[32..32 + 3309];
    let pk_bytes = &input[32 + 3309..];

    // ── Decode public key ─────────────────────────────────────────────────────
    let pk = match decode_verifying_key(pk_bytes) {
        Some(pk) => pk,
        None => return Ok(PrecompileOutput::new(MLDSA_VERIFY_GAS, Bytes::copy_from_slice(&OUTPUT_INVALID))),
    };

    // ── Decode signature ──────────────────────────────────────────────────────
    let sig = match decode_signature(sig_bytes) {
        Some(sig) => sig,
        None => return Ok(PrecompileOutput::new(MLDSA_VERIFY_GAS, Bytes::copy_from_slice(&OUTPUT_INVALID))),
    };

    // ── Verify ───────────────────────────────────────────────────────────────
    let result = dilithium::dilithium65::verify(&pk, msg_hash, &sig);
    let output = if result.is_ok() { &OUTPUT_VALID } else { &OUTPUT_INVALID };

    Ok(PrecompileOutput::new(MLDSA_VERIFY_GAS, Bytes::copy_from_slice(output)))
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn decode_verifying_key(bytes: &[u8]) -> Option<dilithium::VerifyingKey<dilithium::MlDsa65>> {
    let encoded = dilithium::EncodedVerifyingKey::<dilithium::MlDsa65>::try_from(bytes).ok()?;
    Some(dilithium::VerifyingKey::decode(&encoded))
}

fn decode_signature(bytes: &[u8]) -> Option<dilithium::Signature<dilithium::MlDsa65>> {
    let encoded = dilithium::EncodedSignature::<dilithium::MlDsa65>::try_from(bytes).ok()?;
    dilithium::Signature::decode(&encoded)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_msg(msg: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use dilithium::signature::{Keypair, Signer};
        use sha3::{Digest, Keccak256};

        let sk = dilithium::dilithium65::keygen();
        let pk_bytes = sk.verifying_key().encode().as_slice().to_vec();

        // msg_hash is what gets signed AND what the precompile receives as input[0..32]
        let msg_hash = Keccak256::digest(msg).to_vec();

        // Sign the hash (not the original message)
        let sig = sk.sign(&msg_hash);
        let sig_bytes = sig.encode().as_slice().to_vec();

        (msg_hash, sig_bytes, pk_bytes)
    }

    fn build_input(hash: &[u8], sig: &[u8], pk: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(INPUT_LEN);
        v.extend_from_slice(hash);
        v.extend_from_slice(sig);
        v.extend_from_slice(pk);
        v
    }

    #[test]
    fn valid_signature_returns_0x01() {
        let msg = b"hello post-quantum world";
        let (hash, sig, pk) = sign_msg(msg);
        let input = build_input(&hash, &sig, &pk);

        let result = ml_dsa_verify(&input, MLDSA_VERIFY_GAS).unwrap();
        assert_eq!(result.bytes.as_ref(), &OUTPUT_VALID, "valid sig must return uint256(1)");
        assert_eq!(result.gas_used, MLDSA_VERIFY_GAS);
    }

    #[test]
    fn wrong_public_key_returns_0x00() {
        let msg = b"hello";
        let (hash, sig, _pk) = sign_msg(msg);
        // Use a different keypair's public key
        let (_, _, wrong_pk) = sign_msg(b"other");
        let input = build_input(&hash, &sig, &wrong_pk);

        let result = ml_dsa_verify(&input, MLDSA_VERIFY_GAS).unwrap();
        assert_eq!(result.bytes.as_ref(), &OUTPUT_INVALID, "wrong pk must return uint256(0)");
    }

    #[test]
    fn tampered_hash_returns_0x00() {
        let msg = b"hello";
        let (mut hash, sig, pk) = sign_msg(msg);
        hash[0] ^= 0xff; // flip a bit
        let input = build_input(&hash, &sig, &pk);

        let result = ml_dsa_verify(&input, MLDSA_VERIFY_GAS).unwrap();
        assert_eq!(result.bytes.as_ref(), &OUTPUT_INVALID);
    }

    #[test]
    fn wrong_input_length_returns_0x00() {
        let result = ml_dsa_verify(&[0u8; 100], MLDSA_VERIFY_GAS).unwrap();
        assert_eq!(result.bytes.as_ref(), &OUTPUT_INVALID);
    }

    #[test]
    fn out_of_gas_returns_error() {
        let result = ml_dsa_verify(&[0u8; INPUT_LEN], MLDSA_VERIFY_GAS - 1);
        assert!(result.is_err());
    }
}
