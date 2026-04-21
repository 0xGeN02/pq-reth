//! Post-quantum RPC types and builders.
//!
//! Provides [`PqRpcTxConverter`] and [`PqEthApiBuilder`] for the PQ node's
//! ETH API.
//!
//! ## Design
//!
//! `PqSignedTransaction` cannot use the default `()` RPC transaction converter
//! because the blanket `FromConsensusTx` impl conflicts (Rust coherence rules).
//! So we provide a custom [`PqRpcTxConverter`] that maps PQ transactions to
//! legacy-format `TxEnvelope::Legacy` with dummy ECDSA signatures.
//!
//! Other converters use defaults:
//! - SimTx: `()` works via `TryIntoSimTx<PqSignedTransaction>` (feature-gated in
//!   reth-rpc-convert)
//! - TxEnv: `()` works via `TryIntoTxEnv<TxEnv, BlockEnv>` (same EVM types as Ethereum)
//! - SignableTxRequest: implemented in reth-rpc-convert (feature-gated), always errors

use alloy_consensus::transaction::Recovered;
use alloy_consensus::{Signed, TxEnvelope, TxLegacy};
use alloy_primitives::{Address, Signature, TxKind, U256};
use alloy_rpc_types_eth::TransactionInfo;
use reth_chainspec::EthereumHardforks;
use reth_ethereum_forks::Hardforks;
use reth_node_api::{FullNodeComponents, FullNodeTypes, HeaderTy, NodeTypes, PrimitivesTy};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_pq_node_primitives::PqPrimitives;
use reth_pq_primitives::PqSignedTransaction;
use reth_provider::ChainSpecProvider;
use reth_rpc_convert::transaction::RpcTxConverter;
use reth_rpc_convert::RpcConvert;
use reth_rpc_eth_api::{helpers::pending_block::BuildPendingEnv, FromEvmError};
use reth_rpc_eth_types::EthApiError;
use reth_rpc_eth_types::receipt::EthReceiptConverter;
use std::convert::Infallible;

// ─── PqRpcTxConverter ────────────────────────────────────────────────────────

/// Converts `PqSignedTransaction` to Ethereum RPC `Transaction<TxEnvelope>`.
///
/// Maps PQ transaction fields to a legacy-format `TxEnvelope::Legacy` with
/// a dummy ECDSA signature (all zeros). This is acceptable for a PQ-only chain
/// where no client would verify ECDSA signatures.
///
/// The `from` field in the response correctly reflects the PQ-derived address.
#[derive(Debug, Clone, Copy, Default)]
pub struct PqRpcTxConverter;

impl
    RpcTxConverter<
        PqSignedTransaction,
        alloy_rpc_types_eth::Transaction<TxEnvelope>,
        TransactionInfo,
    > for PqRpcTxConverter
{
    type Err = Infallible;

    fn convert_rpc_tx(
        &self,
        tx: PqSignedTransaction,
        signer: Address,
        tx_info: TransactionInfo,
    ) -> Result<alloy_rpc_types_eth::Transaction<TxEnvelope>, Self::Err> {
        let legacy = TxLegacy {
            chain_id: Some(tx.tx.chain_id),
            nonce: tx.tx.nonce,
            gas_price: tx.tx.gas_price,
            gas_limit: tx.tx.gas_limit,
            to: tx.tx.to.map_or(TxKind::Create, TxKind::Call),
            value: U256::from(tx.tx.value),
            input: tx.tx.input.clone(),
        };

        let dummy_sig = Signature::new(U256::ZERO, U256::ZERO, false);
        let signed = Signed::new_unchecked(legacy, dummy_sig, tx.hash);
        let envelope = TxEnvelope::Legacy(signed);
        let recovered = Recovered::new_unchecked(envelope, signer);

        Ok(alloy_rpc_types_eth::Transaction::from_transaction(recovered, tx_info))
    }
}

// ─── Type aliases ────────────────────────────────────────────────────────────

/// RPC converter type for the PQ node.
///
/// Uses the standard Ethereum RPC converter with a custom `RpcTxConverter`.
/// All other converter slots (`SimTx`, `TxEnv`, `Header`, `Map`) use the
/// default `()` which works for PQ types.
pub type PqRpcConverterFor<N> = reth_rpc_convert::RpcConverter<
    alloy_network::Ethereum,
    <N as FullNodeComponents>::Evm,
    EthReceiptConverter<<<N as FullNodeTypes>::Provider as ChainSpecProvider>::ChainSpec>,
    (),              // HeaderConverter — default
    (),              // TxInfoMapper — default
    (),              // SimTxConverter — default (via TryIntoSimTx impl in reth-rpc-convert)
    PqRpcTxConverter,
    (),              // TxEnvConverter — default (via TryIntoTxEnv for TransactionRequest)
>;

/// The `EthApi` type for the PQ node.
pub type PqEthApiFor<N> = reth_rpc::EthApi<N, PqRpcConverterFor<N>>;

// ─── PqEthApiBuilder ────────────────────────────────────────────────────────

/// ETH API builder for the PQ node.
///
/// Constructs the standard `EthApi` with a custom `RpcConverter` that replaces
/// only the `RpcTxConverter` with [`PqRpcTxConverter`]. All other converters
/// use the Ethereum defaults.
#[derive(Debug, Default)]
pub struct PqEthApiBuilder;

impl<N> EthApiBuilder<N> for PqEthApiBuilder
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: Hardforks + EthereumHardforks,
            Primitives = PqPrimitives,
        >,
        Evm: reth_evm::ConfigureEvm<
            NextBlockEnvCtx: BuildPendingEnv<HeaderTy<N::Types>>,
        >,
    >,
    EthApiError: FromEvmError<N::Evm>,
    PqRpcConverterFor<N>: RpcConvert<
        Primitives = PrimitivesTy<N::Types>,
        Error = EthApiError,
        Network = alloy_network::Ethereum,
        Evm = N::Evm,
    >,
{
    type EthApi = PqEthApiFor<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        Ok(ctx
            .eth_api_builder()
            .map_converter(|r| r.with_rpc_tx_converter(PqRpcTxConverter))
            .build())
    }
}
