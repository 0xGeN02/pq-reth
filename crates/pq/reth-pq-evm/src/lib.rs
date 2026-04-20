//! # reth-pq-evm
//!
//! Custom [`EvmFactory`] that extends the standard Ethereum EVM with the
//! ML-DSA-65 signature verification precompile at address `0x0100`.
//!
//! ## Usage
//!
//! Wire `PqEvmConfig` into the node builder via a custom `ExecutorBuilder`:
//!
//! ```rust,ignore
//! use reth_pq_evm::PqExecutorBuilder;
//!
//! NodeBuilder::new(node_config)
//!     .with_types::<EthereumNode>()
//!     .with_components(EthereumNode::components().executor(PqExecutorBuilder::default()))
//!     .launch()
//!     .await?;
//! ```

use alloy_evm::{
    eth::{EthEvm, EthEvmContext},
    precompiles::PrecompilesMap,
    revm::{
        context::{BlockEnv, Context, TxEnv},
        context_interface::result::{EVMError, HaltReason},
        inspector::{Inspector, NoOpInspector},
        interpreter::interpreter::EthInterpreter,
        precompile::{Precompile, PrecompileId, Precompiles},
        primitives::hardfork::SpecId,
        MainBuilder, MainContext,
    },
    Database, EvmEnv, EvmFactory,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_pq_precompile::{ml_dsa_verify, MLDSA_VERIFY_ADDRESS};
use std::sync::OnceLock;

// ─── PqEvmFactory ─────────────────────────────────────────────────────────────

/// An [`EvmFactory`] that adds the ML-DSA-65 precompile (`0x0100`) to every
/// hardfork's precompile set, replacing the standard [`EthPrecompiles`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PqEvmFactory;

impl EvmFactory for PqEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        EthEvm<DB, I, PrecompilesMap>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv,
    ) -> Self::Evm<DB, NoOpInspector> {
        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(PrecompilesMap::from_static(pq_precompiles()));
        EthEvm::new(evm, false)
    }

    fn create_evm_with_inspector<
        DB: Database,
        I: Inspector<Self::Context<DB>, EthInterpreter>,
    >(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        EthEvm::new(self.create_evm(db, input).into_inner().with_inspector(inspector), true)
    }
}

// ─── Precompile set ───────────────────────────────────────────────────────────

/// Prague precompiles extended with the ML-DSA-65 verification precompile.
pub fn pq_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let mut precompiles = Precompiles::prague().clone();
        let mldsa = Precompile::new(
            PrecompileId::custom("ml-dsa-65"),
            MLDSA_VERIFY_ADDRESS,
            ml_dsa_verify,
        );
        precompiles.extend([mldsa]);
        precompiles
    })
}

// ─── Convenience type alias & executor builder ────────────────────────────────

/// [`EthEvmConfig`] wired with [`PqEvmFactory`].
pub type PqEvmConfig<C = reth_chainspec::ChainSpec> = EthEvmConfig<C, PqEvmFactory>;

/// Executor builder that wires [`PqEvmConfig`] into the node.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PqExecutorBuilder;

impl<Node> reth_node_builder::components::ExecutorBuilder<Node> for PqExecutorBuilder
where
    Node: reth_node_api::FullNodeTypes<
        Types: reth_node_api::NodeTypes<
            ChainSpec = reth_chainspec::ChainSpec,
            Primitives = reth_ethereum_primitives::EthPrimitives,
        >,
    >,
{
    type EVM = PqEvmConfig;

    async fn build_evm(
        self,
        ctx: &reth_node_builder::BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        Ok(EthEvmConfig::new_with_evm_factory(ctx.chain_spec(), PqEvmFactory::default()))
    }
}
