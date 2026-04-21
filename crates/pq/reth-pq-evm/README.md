# reth-pq-evm

Post-quantum EVM configuration for the `pq-reth` client.

## Components

### `PqEvmFactory`

`EvmFactory` implementation that adds the ML-DSA-65 precompile (`0x0100`) to
every hardfork's precompile set (base: Prague precompiles).

### `PqReceiptBuilder`

`ReceiptBuilder<Transaction=PqSignedTransaction, Receipt=Receipt>`. Maps PQ
transaction type to `TxType::Eip7702` (byte `0x04`) in alloy's enum.

### `PqEvmConfig`

Full `ConfigureEvm` implementation with `Primitives = PqPrimitives`. Wraps:
- `EthBlockExecutorFactory<PqReceiptBuilder, Arc<C>, PqEvmFactory>`
- `EthBlockAssembler<C>` (generic, reused from Ethereum)

```rust
let config = PqEvmConfig::new(chain_spec);
let factory = config.block_executor_factory();
```

### `PqExecutorBuilder`

`ExecutorBuilder<Node>` that wires `PqEvmConfig` into the node builder pipeline.
Requires `Node::Types::Primitives = PqPrimitives`.

## Design Notes

- `EthEvmConfig` hardcodes `Primitives = EthPrimitives`, so `PqEvmConfig` is a
  standalone struct, not a type alias.
- `FromRecoveredTx<PqSignedTransaction> for TxEnv` lives in `reth-pq-primitives`
  due to Rust's orphan rules.
- `EthBlockAssembler` and `EthBlockExecutorFactory` are generic over transaction
  type — reused directly without modification.

## Dependencies

- `reth-pq-primitives` — `PqSignedTransaction`, `PqTxType`
- `reth-pq-node-primitives` — `PqPrimitives`
- `reth-pq-precompile` — `ml_dsa_verify`, `MLDSA_VERIFY_ADDRESS`
