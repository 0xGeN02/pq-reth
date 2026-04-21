//! Post-quantum [`NodePrimitives`] implementation.
//!
//! Defines [`PqPrimitives`] — a [`NodePrimitives`] implementation that wires
//! [`PqSignedTransaction`] (ML-DSA-65) as the node's signed transaction type,
//! replacing the ECDSA-based `TransactionSigned`.
//!
//! All other primitive types (header, receipt) are reused from the standard
//! Ethereum definitions because they are signature-scheme-agnostic.

use reth_ethereum_primitives::Receipt;
use reth_pq_primitives::PqSignedTransaction;
use reth_primitives_traits::NodePrimitives;

/// Post-quantum block — `alloy_consensus::Block` parameterised with
/// [`PqSignedTransaction`] instead of ECDSA `TransactionSigned`.
pub type Block = alloy_consensus::Block<PqSignedTransaction>;

/// Post-quantum block body.
pub type BlockBody = alloy_consensus::BlockBody<PqSignedTransaction>;

/// Post-quantum node primitives.
///
/// Identical to [`EthPrimitives`](reth_ethereum_primitives::EthPrimitives) except
/// the signed transaction type is [`PqSignedTransaction`] (ML-DSA-65) instead of
/// `TransactionSigned` (ECDSA / secp256k1).
///
/// This is the single type that must be threaded through the entire reth node
/// builder to switch the chain from ECDSA to post-quantum signatures.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct PqPrimitives;

impl NodePrimitives for PqPrimitives {
    type Block = Block;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = BlockBody;
    type SignedTx = PqSignedTransaction;
    type Receipt = Receipt;
}
