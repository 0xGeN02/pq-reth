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
        interpreter::{
            instructions::Instruction, interpreter::EthInterpreter, InstructionContext,
            InterpreterTypes,
        },
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
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::sync::OnceLock;

pub use alloy_evm::eth::spec::EthExecutorSpec;
use reth_ethereum_forks::Hardforks;

use alloy_eips::Decodable2718;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use reth_evm::{ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor};
use reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;

// ─── PQHASH opcode (0x21) ─────────────────────────────────────────────────────

/// Opcode byte for PQHASH (SHAKE-256) — adjacent to KECCAK256 (0x20).
pub const PQHASH_OPCODE: u8 = 0x21;

/// Base gas cost for PQHASH (same as KECCAK256).
const PQHASH_BASE_GAS: u64 = 30;

/// Gas cost per 32-byte word for PQHASH (same as KECCAK256).
const PQHASH_WORD_GAS: u64 = 6;

/// Compute the dynamic gas cost for PQHASH based on data length.
#[inline]
const fn pqhash_gas_cost(len: usize) -> u64 {
    let word_count = len.div_ceil(32);
    PQHASH_WORD_GAS * word_count as u64
}

/// PQHASH instruction handler — computes SHAKE-256 of memory data.
///
/// Stack: `(offset, length) → hash_256`
///
/// Same interface as KECCAK256 (0x20) but using SHAKE-256 (XOF with 256-bit output).
/// This provides a quantum-safe hash natively in the EVM, aligned with
/// ML-DSA-65 which uses SHAKE-256 internally.
fn pqhash<WIRE: InterpreterTypes, H: alloy_evm::revm::context_interface::Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    use alloy_evm::revm::interpreter::interpreter_types::{MemoryTr, StackTr};

    // Pop offset and length from stack (length is on top)
    let Some(([offset], top)) = context.interpreter.stack.popn_top() else {
        context.interpreter.halt(alloy_evm::revm::interpreter::InstructionResult::StackUnderflow);
        return;
    };

    // Convert length to usize
    let len = match top.as_limbs() {
        [len, 0, 0, 0] => *len as usize,
        _ => {
            context.interpreter.halt(alloy_evm::revm::interpreter::InstructionResult::InvalidOperandOOG);
            return;
        }
    };

    // Charge dynamic gas for data size
    let dynamic_gas = pqhash_gas_cost(len);
    if !context.interpreter.gas.record_cost(dynamic_gas) {
        context.interpreter.halt(alloy_evm::revm::interpreter::InstructionResult::OutOfGas);
        return;
    }

    let hash = if len == 0 {
        // SHAKE-256 of empty input with 32 bytes output
        let hasher = Shake256::default();
        let mut output = [0u8; 32];
        let mut reader = hasher.finalize_xof();
        reader.read(&mut output);
        alloy_primitives::B256::from(output)
    } else {
        // Convert offset to usize
        let from = match offset.as_limbs() {
            [from, 0, 0, 0] => *from as usize,
            _ => {
                context.interpreter.halt(alloy_evm::revm::interpreter::InstructionResult::InvalidOperandOOG);
                return;
            }
        };

        // Resize memory if needed (charges memory expansion gas)
        let gas_params = context.host.gas_params();
        if let Err(result) = alloy_evm::revm::interpreter::interpreter::resize_memory(
            &mut context.interpreter.gas,
            &mut context.interpreter.memory,
            gas_params,
            from,
            len,
        ) {
            context.interpreter.halt(result);
            return;
        }

        // Read memory and compute SHAKE-256
        let data = context.interpreter.memory.slice_len(from, len);
        let mut hasher = Shake256::default();
        hasher.update(data.as_ref());
        let mut output = [0u8; 32];
        let mut reader = hasher.finalize_xof();
        reader.read(&mut output);
        alloy_primitives::B256::from(output)
    };

    // Push result onto the stack (overwrite top)
    *top = hash.into();
}

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
        let mut evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(PrecompilesMap::from_static(pq_precompiles()));

        // Insert PQHASH opcode (0x21) — SHAKE-256 hash adjacent to KECCAK256 (0x20)
        evm.instruction.insert_instruction(
            PQHASH_OPCODE,
            Instruction::new(pqhash, PQHASH_BASE_GAS),
        );

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
        let mut inner = self.create_evm(db, input).into_inner().with_inspector(inspector);
        // Re-insert PQHASH for inspected EVM (instruction table is rebuilt by with_inspector)
        inner.instruction.insert_instruction(
            PQHASH_OPCODE,
            Instruction::new(pqhash, PQHASH_BASE_GAS),
        );
        EthEvm::new(inner, true)
    }
}

// ─── Precompile set ───────────────────────────────────────────────────────────

/// Helper to create an address from a single byte (for precompile addresses 0x01-0x13).
const fn precompile_addr(byte: u8) -> alloy_primitives::Address {
    let mut addr = [0u8; 20];
    addr[19] = byte;
    alloy_primitives::Address::new(addr)
}

/// Address of the deprecated ecrecover precompile.
const ECRECOVER_ADDRESS: alloy_primitives::Address = precompile_addr(1);

/// Addresses of classical elliptic curve precompiles broken by Shor's algorithm.
///
/// These are disabled on post-quantum chains because a quantum adversary with
/// a sufficiently large quantum computer can solve the Discrete Logarithm Problem
/// (DLP) and the Elliptic Curve DLP in polynomial time.
const DISABLED_CLASSICAL_PRECOMPILES: &[(u8, &str)] = &[
    // BN254 curve operations (used in Groth16 SNARKs)
    (0x06, "bn254 ecAdd"),
    (0x07, "bn254 ecMul"),
    (0x08, "bn254 ecPairing"),
    // KZG point evaluation (EIP-4844) — relies on DLP over BLS12-381
    (0x0a, "kzg point_evaluation"),
    // BLS12-381 curve operations (all broken by Shor's algorithm)
    (0x0b, "bls12_g1Add"),
    (0x0c, "bls12_g1Mul"),
    (0x0d, "bls12_g1Msm"),
    (0x0e, "bls12_g2Add"),
    (0x0f, "bls12_g2Mul"),
    (0x10, "bls12_g2Msm"),
    (0x11, "bls12_pairing"),
    (0x12, "bls12_map_fp_to_g1"),
    (0x13, "bls12_map_fp2_to_g2"),
];

/// Stub that replaces the ECDSA `ecrecover` precompile.
///
/// Returns `PrecompileError::Other` with a descriptive message. In a PQ-only
/// chain, ECDSA recovery has no place — all signature verification uses
/// ML-DSA-65 via the precompile at `0x0100`.
fn ecrecover_disabled(
    _input: &[u8],
    _gas_limit: u64,
) -> alloy_evm::revm::precompile::PrecompileResult {
    Err(alloy_evm::revm::precompile::PrecompileError::Other(
        "ecrecover is disabled on post-quantum chains; use ML-DSA-65 precompile at 0x0100".into(),
    ))
}

/// Stub that replaces classical elliptic curve precompiles.
///
/// These operations rely on the hardness of the Discrete Logarithm Problem
/// which is efficiently solvable by Shor's algorithm on a quantum computer.
fn classical_curve_disabled(
    _input: &[u8],
    _gas_limit: u64,
) -> alloy_evm::revm::precompile::PrecompileResult {
    Err(alloy_evm::revm::precompile::PrecompileError::Other(
        "classical elliptic curve precompile disabled on post-quantum chain (vulnerable to Shor's algorithm)".into(),
    ))
}

/// Prague precompiles with all classical crypto disabled and the
/// ML-DSA-65 verification precompile added at `0x0100`.
///
/// **Disabled (13 precompiles):**
/// - `0x01` ecrecover (ECDSA)
/// - `0x06`-`0x08` BN254 (ecAdd, ecMul, ecPairing)
/// - `0x0a` KZG point evaluation
/// - `0x0b`-`0x13` BLS12-381 (9 operations)
///
/// **Kept (quantum-safe, 5 precompiles):**
/// - `0x02` SHA-256 (hash — Grover reduces to 128-bit, sufficient)
/// - `0x03` RIPEMD-160 (hash)
/// - `0x04` Identity (data copy)
/// - `0x05` `ModExp` (pure arithmetic)
/// - `0x09` Blake2f (hash compression)
///
/// **Added:**
/// - `0x0100` ML-DSA-65 signature verification
pub fn pq_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let mut precompiles = Precompiles::prague().clone();

        // Replace ecrecover (0x01) with a stub that always errors.
        let ecrecover_stub = Precompile::new(
            PrecompileId::custom("ecrecover-disabled"),
            ECRECOVER_ADDRESS,
            ecrecover_disabled,
        );

        // Disable all classical elliptic curve precompiles
        let mut disabled_stubs: Vec<Precompile> = DISABLED_CLASSICAL_PRECOMPILES
            .iter()
            .map(|(byte, name)| {
                Precompile::new(
                    PrecompileId::custom(alloc::format!("{name}-disabled")),
                    precompile_addr(*byte),
                    classical_curve_disabled,
                )
            })
            .collect();

        // Add the ML-DSA-65 precompile
        let mldsa = Precompile::new(
            PrecompileId::custom("ml-dsa-65"),
            MLDSA_VERIFY_ADDRESS,
            ml_dsa_verify,
        );

        disabled_stubs.push(ecrecover_stub);
        disabled_stubs.push(mldsa);
        precompiles.extend(disabled_stubs);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecrecover_is_disabled() {
        let precompiles = pq_precompiles();
        // ecrecover at 0x01 should still exist (not removed) but be a disabled stub
        assert!(
            precompiles.contains(&ECRECOVER_ADDRESS),
            "ecrecover address should be present (replaced, not removed)"
        );
        // Calling it should return an error
        let result = precompiles.get(&ECRECOVER_ADDRESS).unwrap().execute(&[0u8; 128], 100_000);
        assert!(result.is_err(), "ecrecover should return error on PQ chain");
    }

    #[test]
    fn mldsa_precompile_present() {
        let precompiles = pq_precompiles();
        assert!(
            precompiles.contains(&MLDSA_VERIFY_ADDRESS),
            "ML-DSA precompile at 0x0100 should be present"
        );
    }

    #[test]
    fn standard_precompiles_still_available() {
        let precompiles = pq_precompiles();
        // SHA-256 at 0x02 should still work
        assert!(
            precompiles.contains(&precompile_addr(0x02)),
            "SHA-256 precompile at 0x02 should still be present"
        );
        // RIPEMD-160 at 0x03
        assert!(precompiles.contains(&precompile_addr(0x03)));
        // Identity at 0x04
        assert!(precompiles.contains(&precompile_addr(0x04)));
        // ModExp at 0x05
        assert!(precompiles.contains(&precompile_addr(0x05)));
        // Blake2f at 0x09
        assert!(precompiles.contains(&precompile_addr(0x09)));
    }

    #[test]
    fn classical_curve_precompiles_disabled() {
        let precompiles = pq_precompiles();
        // All classical curve precompiles should exist but return errors
        for (byte, name) in DISABLED_CLASSICAL_PRECOMPILES {
            let addr = precompile_addr(*byte);
            assert!(
                precompiles.contains(&addr),
                "{name} at 0x{byte:02x} should be present (disabled stub)"
            );
            let result = precompiles.get(&addr).unwrap().execute(&[0u8; 128], 100_000);
            assert!(
                result.is_err(),
                "{name} at 0x{byte:02x} should return error on PQ chain"
            );
        }
    }

    #[test]
    fn pqhash_gas_cost_calculation() {
        // 0 bytes → 0 words → 0 dynamic gas
        assert_eq!(pqhash_gas_cost(0), 0);
        // 1 byte → 1 word → 6 gas
        assert_eq!(pqhash_gas_cost(1), 6);
        // 32 bytes → 1 word → 6 gas
        assert_eq!(pqhash_gas_cost(32), 6);
        // 33 bytes → 2 words → 12 gas
        assert_eq!(pqhash_gas_cost(33), 12);
        // 64 bytes → 2 words → 12 gas
        assert_eq!(pqhash_gas_cost(64), 12);
    }

    #[test]
    fn pqhash_shake256_known_vector() {
        // Verify our SHAKE-256 implementation matches known output
        // SHAKE-256("") with 32 bytes output
        let hasher = Shake256::default();
        let mut output = [0u8; 32];
        let mut reader = hasher.finalize_xof();
        reader.read(&mut output);
        // Known SHAKE-256("", 32) = 46b9dd2b0ba88d13...
        assert_eq!(output[0], 0x46);
        assert_eq!(output[1], 0xb9);

        // SHAKE-256("abc") with 32 bytes output
        let mut hasher2 = Shake256::default();
        hasher2.update(b"abc");
        let mut output2 = [0u8; 32];
        let mut reader2 = hasher2.finalize_xof();
        reader2.read(&mut output2);
        // Known SHAKE-256("abc", 32) = 483366601573f85f...
        assert_eq!(output2[0], 0x48);
        assert_eq!(output2[1], 0x33);
    }
}
