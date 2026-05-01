//! [`Compact`] codec implementation for [`PqSignedTransaction`].
//!
//! This enables database storage of PQ transactions when the `reth-codec`
//! feature is active.
//!
//! Wire format:
//! ```text
//! chain_id (8 bytes, big-endian)
//! nonce    (8 bytes, big-endian)
//! gas_price (16 bytes, big-endian)
//! gas_limit (8 bytes, big-endian)
//! has_to   (1 byte)  — 0x00 = create, 0x01 = call
//! [to]     (20 bytes, only if has_to == 0x01)
//! value    (16 bytes, big-endian)
//! input_len (4 bytes, big-endian)
//! input    (input_len bytes)
//! signature (3309 bytes)
//! public_key (1952 bytes)
//! ```

use alloy_primitives::Bytes;
use bytes::BufMut;
use reth_codecs::Compact;
use reth_db_api::table::{Compress, Decompress};

use crate::{
    signature::{PqPublicKey, PqSignature},
    transaction::{PqSignedTransaction, PqTransactionRequest},
};

impl Compact for PqSignedTransaction {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        let start_len = buf.as_mut().len();

        // Unsigned fields
        buf.put_u64(self.tx.chain_id);
        buf.put_u64(self.tx.nonce);
        buf.put_u128(self.tx.gas_price);
        buf.put_u64(self.tx.gas_limit);

        match self.tx.to {
            Some(addr) => {
                buf.put_u8(0x01);
                buf.put_slice(addr.as_slice());
            }
            None => {
                buf.put_u8(0x00);
            }
        }

        buf.put_u128(self.tx.value);

        let input_len = self.tx.input.len() as u32;
        buf.put_u32(input_len);
        buf.put_slice(&self.tx.input);

        // Signature + public key (fixed sizes: 3309 + 1952)
        buf.put_slice(self.signature.as_bytes());
        buf.put_slice(self.public_key.as_bytes());

        // Return the number of bytes written.
        // The hash is NOT stored — it is recomputed on decode.
        let written = buf.as_mut().len() - start_len;
        written
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use alloy_primitives::Address;

        let chain_id = u64::from_be_bytes(buf[..8].try_into().unwrap());
        buf = &buf[8..];

        let nonce = u64::from_be_bytes(buf[..8].try_into().unwrap());
        buf = &buf[8..];

        let gas_price = u128::from_be_bytes(buf[..16].try_into().unwrap());
        buf = &buf[16..];

        let gas_limit = u64::from_be_bytes(buf[..8].try_into().unwrap());
        buf = &buf[8..];

        let has_to = buf[0];
        buf = &buf[1..];
        let to = if has_to == 0x01 {
            let addr = Address::from_slice(&buf[..20]);
            buf = &buf[20..];
            Some(addr)
        } else {
            None
        };

        let value = u128::from_be_bytes(buf[..16].try_into().unwrap());
        buf = &buf[16..];

        let input_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        buf = &buf[4..];
        let input = Bytes::copy_from_slice(&buf[..input_len]);
        buf = &buf[input_len..];

        // Fixed-size signature (3309 bytes)
        let sig_bytes = buf[..3309].to_vec();
        buf = &buf[3309..];

        // Fixed-size public key (1952 bytes)
        let pk_bytes = buf[..1952].to_vec();
        buf = &buf[1952..];

        let tx = PqTransactionRequest { chain_id, nonce, gas_price, gas_limit, to, value, input };
        let signature = PqSignature::from_bytes(sig_bytes);
        let public_key = PqPublicKey::from_bytes(pk_bytes);
        let signed = PqSignedTransaction::new(tx, signature, public_key);

        (signed, buf)
    }
}

// ─── Database Compress / Decompress ──────────────────────────────────────────

impl Compress for PqSignedTransaction {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let _ = Compact::to_compact(self, buf);
    }
}

impl Decompress for PqSignedTransaction {
    fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        let (obj, _) = Compact::from_compact(value, value.len());
        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PqSigner;
    use alloy_primitives::{Address, Bytes};

    #[test]
    fn compact_roundtrip() {
        let signer = PqSigner::generate();
        let tx = PqTransactionRequest {
            nonce: 42,
            to: Some(Address::from([0xab; 20])),
            value: 1_000_000_000_000_000_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            input: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            chain_id: 1337,
        };
        let signed = signer.sign_transaction(tx);

        let mut buf = Vec::with_capacity(8192);
        let written = signed.to_compact(&mut buf);
        assert!(written > 0, "must write bytes");

        let (decoded, rest) = PqSignedTransaction::from_compact(&buf, written);
        assert!(rest.is_empty(), "all bytes must be consumed");
        assert_eq!(decoded.tx, signed.tx, "unsigned fields must match");
        assert_eq!(decoded.hash, signed.hash, "hash must match (recomputed)");
    }

    #[test]
    fn compact_roundtrip_contract_creation() {
        let signer = PqSigner::generate();
        let tx = PqTransactionRequest {
            nonce: 0,
            to: None,
            value: 0,
            gas_limit: 100_000,
            gas_price: 2_000_000_000,
            input: Bytes::from_static(&[0x60, 0x80, 0x60, 0x40]),
            chain_id: 1,
        };
        let signed = signer.sign_transaction(tx);

        let mut buf = Vec::with_capacity(8192);
        let written = signed.to_compact(&mut buf);

        let (decoded, rest) = PqSignedTransaction::from_compact(&buf, written);
        assert!(rest.is_empty());
        assert_eq!(decoded.tx.to, None);
        assert_eq!(decoded.hash, signed.hash);
    }
}
