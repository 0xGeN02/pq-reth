//! # reth-pq-evm
//!
//! Post-quantum EVM configuration for the `pq-reth` client.
//!
//! Provides:
//! - [`PqEvmFactory`] — [`EvmFactory`] with the ML-DSA-65 precompile at `0x0100`
//! - [`PqReceiptBuilder`] — [`ReceiptBuilder`] for PQ transactions
//! - [`PqEvmConfig`] — full [`ConfigureEvm`] implementation with `Primitives = PqPrimitives`
//! - [`PqExecutorBuilder`] — wires the EVM config into the node builder
//!
//! The `FromRecoveredTx<PqSignedTransaction>` and `FromTxWithEncoded<PqSignedTransaction>`
//! impls for `TxEnv` live in `reth-pq-primitives::tx_env` (orphan rules require the local
//! type to be in the implementing crate).

extern crate alloc;

use alloc::borrow::Cow;
use alloc::sync::Arc;
use alloy_consensus::Header;
use alloy_evm::{
    eth::{
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
        EthBlockExecutionCtx, EthBlockExecutorFactory, EthEvm, EthEvmContext,
    },
    precompiles::PrecompilesMap,
    revm::{
        context::{BlockEnv, CfgEnv, Context, TxEnv},
        context_interface::{
            block::BlobExcessGasAndPrice,
            result::{EVMError, HaltReason},
        },
        inspector::{Inspector, NoOpInspector},
        interpreter::interpreter::EthInterpreter,
        precompile::{Precompile, PrecompileId, Precompiles},
        primitives::hardfork::SpecId,
        MainBuilder, MainContext,
    },
    Database, Evm as EvmTrait, EvmEnv, EvmFactory,
};
use core::convert::Infallible;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::Receipt;
use reth_evm::{
    eth::NextEvmEnvAttributes, ConfigureEvm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::EthBlockAssembler;
use reth_pq_node_primitives::PqPrimitives;
use reth_pq_precompile::{ml_dsa_verify, MLDSA_VERIFY_ADDRESS};
use reth_pq_primitives::{PqSignedTransaction, PqTxType};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use std::sync::OnceLock;

pub use alloy_evm::eth::spec::EthExecutorSpec;
use reth_ethereum_forks::Hardforks;

use alloy_eips::Decodable2718;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use reth_evm::{ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor};
use reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;

// ─── PqEvmFactory ─────────────────────────────────────────────────────────────

/// An [`EvmFactory`] that adds the ML-DSA-65 precompile (`0x0100`) to every
/// hardfork's precompile set.
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

// ─── PqReceiptBuilder ────────────────────────────────────────────────────────

/// Receipt builder for post-quantum transactions.
///
/// Produces [`Receipt`] (`EthereumReceipt<TxType>`) from PQ transaction execution
/// results. Maps the PQ transaction type to `TxType::Eip7702` (byte 0x04) since
/// that's the matching alloy enum variant.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PqReceiptBuilder;

impl ReceiptBuilder for PqReceiptBuilder {
    type Transaction = PqSignedTransaction;
    type Receipt = Receipt;

    fn build_receipt<E: EvmTrait>(
        &self,
        ctx: ReceiptBuilderCtx<'_, PqTxType, E>,
    ) -> Self::Receipt {
        let ReceiptBuilderCtx { result, cumulative_gas_used, .. } = ctx;
        // In our fork, PQ_TX_TYPE = 0x04 maps to TxType::Eip7702 in alloy's enum.
        // This is acceptable because we don't support any classic Ethereum tx types.
        Receipt {
            tx_type: alloy_consensus::TxType::Eip7702,
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs(),
        }
    }
}

// ─── PqEvmConfig ─────────────────────────────────────────────────────────────

/// Post-quantum EVM configuration.
///
/// Wraps [`EthBlockExecutorFactory`] with [`PqReceiptBuilder`] and [`PqEvmFactory`],
/// providing `ConfigureEvm` with `Primitives = PqPrimitives`.
#[derive(Debug, Clone)]
pub struct PqEvmConfig<C = ChainSpec> {
    /// Inner block executor factory.
    pub executor_factory: EthBlockExecutorFactory<PqReceiptBuilder, Arc<C>, PqEvmFactory>,
    /// Block assembler (reused from Ethereum — generic over tx type).
    pub block_assembler: EthBlockAssembler<C>,
}

impl PqEvmConfig {
    /// Creates a PQ EVM configuration with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            block_assembler: EthBlockAssembler::new(chain_spec.clone()),
            executor_factory: EthBlockExecutorFactory::new(
                PqReceiptBuilder::default(),
                chain_spec,
                PqEvmFactory::default(),
            ),
        }
    }
}

impl<C> PqEvmConfig<C> {
    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<C> {
        self.executor_factory.spec()
    }
}

impl<C> ConfigureEvm for PqEvmConfig<C>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
{
    type Primitives = PqPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = EthBlockExecutorFactory<PqReceiptBuilder, Arc<C>, PqEvmFactory>;
    type BlockAssembler = EthBlockAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        Ok(EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(header.timestamp),
        ))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
            },
            self.chain_spec().next_block_base_fee(parent, attributes.timestamp).unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
        ))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<alloy_consensus::Block<PqSignedTransaction>>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        use alloy_consensus::BlockHeader;
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.body().transactions.len()),
            parent_hash: block.header().parent_hash(),
            parent_beacon_block_root: block.header().parent_beacon_block_root(),
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data().clone(),
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            extra_data: attributes.extra_data,
        })
    }
}

// ─── ConfigureEngineEvm ──────────────────────────────────────────────────────

impl<C> ConfigureEngineEvm<ExecutionData> for PqEvmConfig<C>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + EthereumHardforks + Hardforks + 'static,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();

        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);
        let spec = alloy_evm::spec_by_timestamp_and_block_number(
            self.chain_spec(),
            timestamp,
            block_number,
        );

        let mut cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec_and_mainnet_gas_params(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        let blob_excess_gas_and_price =
            payload.payload.excess_blob_gas().zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary: payload.payload.fee_recipient(),
            timestamp: U256::from(timestamp),
            difficulty: if spec >= SpecId::MERGE {
                U256::ZERO
            } else {
                payload.payload.as_v1().prev_randao.into()
            },
            prevrandao: (spec >= SpecId::MERGE).then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.gas_limit(),
            basefee: payload.payload.saturated_base_fee_per_gas(),
            blob_excess_gas_and_price,
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let convert = |tx: Bytes| {
            let tx =
                TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };

        Ok((txs, convert))
    }
}

// ─── PqExecutorBuilder ───────────────────────────────────────────────────────

/// Executor builder that wires [`PqEvmConfig`] into the node.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PqExecutorBuilder;

impl<Node> reth_node_builder::components::ExecutorBuilder<Node> for PqExecutorBuilder
where
    Node: reth_node_api::FullNodeTypes<
        Types: reth_node_api::NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = PqPrimitives,
        >,
    >,
{
    type EVM = PqEvmConfig;

    async fn build_evm(
        self,
        ctx: &reth_node_builder::BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        Ok(PqEvmConfig::new(ctx.chain_spec()))
    }
}
