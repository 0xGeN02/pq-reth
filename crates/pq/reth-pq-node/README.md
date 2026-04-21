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
    type Payload = PqEngineTypes;
}
```

### `PqEngineTypes`

Full `EngineTypes` implementation. Uses standard Ethereum execution payload
envelope types (V1-V6). Works because `from_block_unchecked` only requires
`T: Encodable2718 + Transaction`, both implemented by `PqSignedTransaction`.

### `PqBuiltPayload`

Newtype wrapper around `EthBuiltPayload<PqPrimitives>`. Provides
`From`/`TryInto` conversions to all `ExecutionPayloadEnvelope*` types.
Required due to orphan rules (can't add foreign trait impls on foreign
generic types).

PQ transactions have no blob sidecars — blob bundles are always empty.

### `PqPoolBuilder`

`PoolBuilder<Node, Evm>` that creates a transaction pool with:
- `PqPoolValidator` — ML-DSA-65 signature verification
- `CoinbaseTipOrdering<PqPooledTransaction>` — transaction ordering
- `DiskFileBlobStore` — no-op blob store (PQ txs have no blobs)

### `PqPayloadTypes`

`PayloadTypes` impl with `BuiltPayload = PqBuiltPayload`. Reuses Ethereum
payload attributes (signature-agnostic).

### `PqConsensusBuilder`

`ConsensusBuilder<Node>` wrapping `EthBeaconConsensus`. Block-level validation
rules (gas, timestamp, etc.) are signature-type agnostic.

### `PqNetworkBuilder`

`NetworkBuilder<Node, Pool>` reusing the standard Ethereum networking stack.

## Status

| Component | Status |
|-----------|--------|
| `NodeTypes` impl | Complete |
| `PqPoolBuilder` | Complete |
| `PqEngineTypes` + `PqBuiltPayload` | Complete |
| `PqConsensusBuilder` | Complete |
| `PqNetworkBuilder` | Complete |
| `PqExecutorBuilder` | Complete (in `reth-pq-evm`) |
| `Node<N>` wiring | Pending |

### Pending: `Node<N>` trait impl

Requires:
1. **PQ payload builder** — `EthereumPayloadBuilder` is hardcoded to
   `Primitives = EthPrimitives`
2. **`EngineTypes` ↔ payload builder** — the payload builder must produce
   `PqBuiltPayload` instances

### Pending: `PqAddOns`

`EthereumAddOns` hardcodes `Primitives = EthPrimitives`. Options:
- Create `PqAddOns` wrapping `RpcAddOns` with PQ types
- Use `()` (no RPC/engine API) for block execution testing

## Re-exports

This crate re-exports key types from `reth-pq-evm`:
- `PqEvmConfig`
- `PqEvmFactory`
- `PqExecutorBuilder`
- `PqReceiptBuilder`
