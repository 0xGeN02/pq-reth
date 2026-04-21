# reth-pq-node

Post-quantum Ethereum node definition for the `pq-reth` client.

## Components

### `PqNode`

Implements `NodeTypes` with `Primitives = PqPrimitives`:

```rust
impl NodeTypes for PqNode {
    type Primitives = PqPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = PqPayloadTypes;
}
```

### `PqPayloadTypes`

`PayloadTypes` impl reusing Ethereum payload attributes (signature-agnostic)
with `EthBuiltPayload<PqPrimitives>`.

### `PqConsensusBuilder`

`ConsensusBuilder<Node>` wrapping `EthBeaconConsensus`. Block-level validation
rules (gas, timestamp, etc.) are signature-type agnostic.

### `PqNetworkBuilder`

`NetworkBuilder<Node, Pool>` reusing the standard Ethereum networking stack.

## Status

| Component | Status |
|-----------|--------|
| `NodeTypes` impl | Complete |
| `PqConsensusBuilder` | Complete |
| `PqNetworkBuilder` | Complete |
| `PqExecutorBuilder` | Complete (in `reth-pq-evm`) |
| `Node<N>` wiring | Pending |

### Pending: `Node<N>` trait impl

Requires:
1. **PQ transaction pool** — `EthTransactionPool` is hardcoded to
   `TransactionSigned` via `EthPooledTransaction`
2. **PQ payload builder** — needs `EngineTypes` with
   `TryInto<ExecutionPayloadEnvelope*>` conversions
3. **`EngineTypes` impl** — `EthEngineTypes` hardcodes
   `BuiltPayload::Primitives::Block = reth_ethereum_primitives::Block`

## Re-exports

This crate re-exports key types from `reth-pq-evm`:
- `PqEvmConfig`
- `PqEvmFactory`
- `PqExecutorBuilder`
- `PqReceiptBuilder`
