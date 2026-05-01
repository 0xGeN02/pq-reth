//! RLP encoding/decoding and EIP-2718 support for [`PqSignedTransaction`].
//!
//! Wire format for type-0x04 PQ transactions:
//!
//! ```text
//! 0x04 || RLP([
//!   chain_id,
//!   nonce,
//!   gas_price,
//!   gas_limit,
//!   to,          -- empty list for contract creation
//!   value,
//!   input,
//!   signature,   -- raw bytes (3309)
//!   public_key,  -- raw bytes (1952)
//! ])
//! ```

use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

use crate::{
    signature::{PqPublicKey, PqSignature},
    transaction::{PqSignedTransaction, PqTransactionRequest, PQ_TX_TYPE},
};

// ─── RLP helper structs ───────────────────────────────────────────────────────
// We derive RlpEncodable/Decodable on a flat struct to keep things simple.

#[derive(RlpEncodable, RlpDecodable)]
struct PqTxRlpFields {
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    /// Empty bytes = contract creation (no `to`).
    to: Bytes,
    value: U256,
    input: Bytes,
    /// Raw ML-DSA-65 signature bytes.
    signature: Bytes,
    /// Raw ML-DSA-65 public key bytes.
    public_key: Bytes,
}

// ─── Encodable (legacy RLP — used by some internal reth paths) ────────────────

impl Encodable for PqSignedTransaction {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        // EIP-2718: prefix with type byte, then RLP payload
        out.put_u8(PQ_TX_TYPE);
        self.rlp_fields().encode(out);
    }

    fn length(&self) -> usize {
        1 + self.rlp_fields().length()
    }
}

impl Decodable for PqSignedTransaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // Consume type byte
        if buf.is_empty() || buf[0] != PQ_TX_TYPE {
            return Err(alloy_rlp::Error::Custom("expected PQ tx type 0x04"));
        }
        *buf = &buf[1..];
        let fields = PqTxRlpFields::decode(buf)?;
        Ok(Self::from_rlp_fields(fields))
    }
}

// ─── EIP-2718 ─────────────────────────────────────────────────────────────────

impl Encodable2718 for PqSignedTransaction {
    fn type_flag(&self) -> Option<u8> {
        Some(PQ_TX_TYPE)
    }

    fn encode_2718_len(&self) -> usize {
        // type byte + RLP payload
        1 + self.rlp_fields().length()
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(PQ_TX_TYPE);
        self.rlp_fields().encode(out);
    }
}

impl Decodable2718 for PqSignedTransaction {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> alloy_eips::eip2718::Eip2718Result<Self> {
        if ty != PQ_TX_TYPE {
            return Err(alloy_eips::eip2718::Eip2718Error::UnexpectedType(ty));
        }
        let fields = PqTxRlpFields::decode(buf).map_err(|_| {
            alloy_eips::eip2718::Eip2718Error::RlpError(alloy_rlp::Error::Custom(
                "rlp decode failed",
            ))
        })?;
        Ok(Self::from_rlp_fields(fields))
    }

    fn fallback_decode(_buf: &mut &[u8]) -> alloy_eips::eip2718::Eip2718Result<Self> {
        Err(alloy_eips::eip2718::Eip2718Error::UnexpectedType(0x00))
    }
}

// ─── Helpers on PqSignedTransaction ──────────────────────────────────────────

impl PqSignedTransaction {
    fn rlp_fields(&self) -> PqTxRlpFields {
        PqTxRlpFields {
            chain_id: self.tx.chain_id,
            nonce: self.tx.nonce,
            gas_price: self.tx.gas_price,
            gas_limit: self.tx.gas_limit,
            to: match self.tx.to {
                Some(addr) => Bytes::copy_from_slice(addr.as_slice()),
                None => Bytes::new(),
            },
            value: U256::from(self.tx.value),
            input: self.tx.input.clone(),
            signature: Bytes::copy_from_slice(self.signature.as_bytes()),
            public_key: Bytes::copy_from_slice(self.public_key.as_bytes()),
        }
    }

    fn from_rlp_fields(f: PqTxRlpFields) -> Self {
        let to = if f.to.is_empty() {
            None
        } else if f.to.len() == 20 {
            Some(Address::from_slice(&f.to))
        } else {
            None
        };

        let tx = PqTransactionRequest {
            chain_id: f.chain_id,
            nonce: f.nonce,
            gas_price: f.gas_price,
            gas_limit: f.gas_limit,
            to,
            value: f.value.to::<u128>(),
            input: f.input,
        };

        Self::new(
            tx,
            PqSignature::from_bytes(f.signature.to_vec()),
            PqPublicKey::from_bytes(f.public_key.to_vec()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};

    fn make_signed_tx() -> PqSignedTransaction {
        let tx = PqTransactionRequest {
            chain_id: 20561,
            nonce: 42,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: Some(Address::from([0xab; 20])),
            value: 1_000_000_000_000_000_000,
            input: Bytes::new(),
        };
        PqSignedTransaction::new(
            tx,
            PqSignature::from_bytes(vec![0xaa; 3309]),
            PqPublicKey::from_bytes(vec![0xbb; 1952]),
        )
    }

    #[test]
    fn encode_decode_2718_roundtrip() {
        let original = make_signed_tx();
        let mut encoded = Vec::new();
        original.encode_2718(&mut encoded);

        // First byte is the type
        assert_eq!(encoded[0], PQ_TX_TYPE);

        // Decode it back
        let decoded = PqSignedTransaction::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.tx.chain_id, original.tx.chain_id);
        assert_eq!(decoded.tx.nonce, original.tx.nonce);
        assert_eq!(decoded.tx.gas_price, original.tx.gas_price);
        assert_eq!(decoded.tx.gas_limit, original.tx.gas_limit);
        assert_eq!(decoded.tx.to, original.tx.to);
        assert_eq!(decoded.tx.value, original.tx.value);
        assert_eq!(decoded.tx.input, original.tx.input);
        assert_eq!(decoded.signature.as_bytes(), original.signature.as_bytes());
        assert_eq!(decoded.public_key.as_bytes(), original.public_key.as_bytes());
    }

    #[test]
    fn encode_decode_legacy_rlp_roundtrip() {
        let original = make_signed_tx();
        let mut buf = Vec::new();
        original.encode(&mut buf);

        let decoded = PqSignedTransaction::decode(&mut &buf[..]).unwrap();
        assert_eq!(decoded.tx.chain_id, original.tx.chain_id);
        assert_eq!(decoded.tx.nonce, original.tx.nonce);
        assert_eq!(decoded.tx.to, original.tx.to);
        assert_eq!(decoded.tx.value, original.tx.value);
    }

    #[test]
    fn wallet_format_decodes_on_node() {
        // Simulate what the wallet produces:
        // 0x04 || RLP([chain_id, nonce, gas_price, gas_limit, to, value, input, sig, pk])
        //
        // We manually build the RLP using the same struct the node uses.
        let fields = PqTxRlpFields {
            chain_id: 20561,
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: Bytes::copy_from_slice(&[0xde; 20]),
            value: U256::from(1_000_000_000_000_000_000u128),
            input: Bytes::new(),
            signature: Bytes::copy_from_slice(&vec![0x11; 3309]),
            public_key: Bytes::copy_from_slice(&vec![0x22; 1952]),
        };

        let mut raw = vec![PQ_TX_TYPE];
        fields.encode(&mut raw);

        // Node should decode this successfully
        let decoded = PqSignedTransaction::decode_2718(&mut &raw[..]).unwrap();
        assert_eq!(decoded.tx.chain_id, 20561);
        assert_eq!(decoded.tx.nonce, 0);
        assert_eq!(decoded.tx.gas_limit, 21_000);
        assert_eq!(decoded.tx.to, Some(Address::from([0xde; 20])));
        assert_eq!(decoded.signature.as_bytes().len(), 3309);
        assert_eq!(decoded.public_key.as_bytes().len(), 1952);
    }

    #[test]
    fn contract_creation_encodes_correctly() {
        let tx = PqTransactionRequest {
            chain_id: 20561,
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 100_000,
            to: None,  // contract creation
            value: 0,
            input: Bytes::from(vec![0x60, 0x80, 0x60, 0x40, 0x52]),
        };
        let signed = PqSignedTransaction::new(
            tx,
            PqSignature::from_bytes(vec![0xcc; 3309]),
            PqPublicKey::from_bytes(vec![0xdd; 1952]),
        );

        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        let decoded = PqSignedTransaction::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.tx.to, None);
        assert_eq!(decoded.tx.input.as_ref(), &[0x60, 0x80, 0x60, 0x40, 0x52]);
    }
}
