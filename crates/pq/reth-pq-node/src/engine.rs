//! Post-quantum engine validator.
//!
//! Provides [`PqEngineValidator`] — validates Engine API payloads for the PQ node.
//!
//! Mirrors [`EthereumEngineValidator`](reth_ethereum_node::engine::EthereumEngineValidator)
//! but converts payloads to `Block<PqSignedTransaction>` instead of
//! `Block<TransactionSigned>`.
//!
//! The underlying [`EthereumExecutionPayloadValidator::ensure_well_formed_payload`]
//! is generic over `T: SignedTransaction`, so `PqSignedTransaction` works directly.

use alloy_consensus::Block;
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_node_api::PayloadTypes;
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_pq_primitives::PqSignedTransaction;
use reth_primitives_traits::SealedBlock;
use std::sync::Arc;

pub use reth_ethereum_engine_primitives::EthPayloadAttributes;

/// Engine API validator for the PQ node.
///
/// Structurally identical to `EthereumEngineValidator` but with
/// `type Block = Block<PqSignedTransaction>`.
///
/// The payload conversion delegates to
/// [`EthereumExecutionPayloadValidator::ensure_well_formed_payload`]
/// which is generic over `T: SignedTransaction` — so it works with
/// `PqSignedTransaction` out of the box.
#[derive(Debug, Clone)]
pub struct PqEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl<ChainSpec> PqEngineValidator<ChainSpec> {
    /// Creates a new PQ engine validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthereumExecutionPayloadValidator::new(chain_spec) }
    }

    /// Returns the chain spec.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        // EthereumExecutionPayloadValidator::chain_spec returns &Arc<ChainSpec>
        self.inner.chain_spec()
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for PqEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block<PqSignedTransaction>;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        self.inner.ensure_well_formed_payload(payload).map_err(Into::into)
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for PqEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Types::ExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}
