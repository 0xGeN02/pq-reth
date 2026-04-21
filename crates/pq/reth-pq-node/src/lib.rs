//! # reth-pq-node
//!
//! Post-quantum Ethereum node definition.
//!
//! Provides [`PqNode`] — a [`NodeTypes`] implementation that wires
//! post-quantum components (ML-DSA-65 signatures, PQ precompile) into
//! the reth node builder pipeline.
//!
//! ## Architecture
//!
//! The PQ node reuses most Ethereum infrastructure but replaces:
//! - Transaction primitives (`PqSignedTransaction` instead of `TransactionSigned`)
//! - EVM configuration (`PqEvmConfig` with ML-DSA precompile)
//! - Receipt builder (`PqReceiptBuilder` for PQ transaction types)
//!
//! ## Status
//!
//! - `NodeTypes` impl: **complete**
//! - `PqExecutorBuilder`: **complete** (in `reth-pq-evm`)
//! - `PqConsensusBuilder`: **complete**
//! - `Node<N>` wiring: **pending** (requires PQ-specific pool and payload builders)

use std::sync::Arc;

use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, PeersInfo};
use reth_node_api::{FullNodeTypes, NodePrimitives, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{ConsensusBuilder, NetworkBuilder},
    node::NodeTypes,
    BuilderContext,
};
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_pq_node_primitives::PqPrimitives;
use reth_primitives_traits::SealedBlock;
use reth_provider::EthStorage;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use tracing::info;

// Re-export key types for downstream use
pub use reth_pq_evm::{PqEvmConfig, PqEvmFactory, PqExecutorBuilder, PqReceiptBuilder};

// ─── PqPayloadTypes ──────────────────────────────────────────────────────────

/// Payload types for the PQ node.
///
/// Reuses Ethereum payload attributes (which are signature-agnostic) but
/// with `EthBuiltPayload<PqPrimitives>` for the built payload.
///
/// **Note:** Engine API conversions (`TryInto<ExecutionPayloadEnvelope*>`) are
/// not yet implemented — this means `EngineTypes` is not satisfied.
/// Sufficient for block execution testing but not full CL integration.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct PqPayloadTypes;

impl PayloadTypes for PqPayloadTypes {
    type BuiltPayload = EthBuiltPayload<PqPrimitives>;
    type PayloadAttributes = EthPayloadAttributes;
    type PayloadBuilderAttributes = EthPayloadBuilderAttributes;
    type ExecutionData = alloy_rpc_types_engine::ExecutionData;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        let hash = block.hash();
        let block = block.into_block();
        let (payload, sidecar) =
            alloy_rpc_types_engine::ExecutionPayload::from_block_unchecked(hash, &block);
        alloy_rpc_types_engine::ExecutionData { payload, sidecar }
    }
}

// ─── PqNode ──────────────────────────────────────────────────────────────────

/// Post-quantum Ethereum node type.
///
/// Implements [`NodeTypes`] with `Primitives = PqPrimitives`.
///
/// The full `Node<N>` impl (providing `ComponentsBuilder` and `AddOns`) is
/// pending — it requires:
/// - A PQ-specific transaction pool (standard `EthTransactionPool` is
///   hardcoded to `TransactionSigned`)
/// - A PQ payload builder
///
/// Block execution can be tested directly via [`PqEvmConfig`]'s
/// `block_executor_factory()`.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PqNode;

impl NodeTypes for PqNode {
    type Primitives = PqPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = PqPayloadTypes;
}

// ─── PqNetworkBuilder ────────────────────────────────────────────────────────

/// Network builder for the PQ node.
///
/// Reuses the standard Ethereum networking stack — the P2P protocol is
/// transaction-type agnostic at this layer.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PqNetworkBuilder;

impl<Node, Pool> NetworkBuilder<Node, Pool> for PqNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: reth_ethereum_forks::Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network = ctx.network_builder().await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "PQ P2P networking initialized");
        Ok(handle)
    }
}

// ─── PqConsensusBuilder ──────────────────────────────────────────────────────

/// Consensus builder for the PQ node.
///
/// Uses `EthBeaconConsensus` which validates block-level rules (gas, timestamp,
/// etc.) without depending on transaction signature type.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PqConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for PqConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: EthChainSpec + EthereumHardforks,
            Primitives = PqPrimitives,
        >,
    >,
{
    type Consensus = Arc<EthBeaconConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
    }
}
