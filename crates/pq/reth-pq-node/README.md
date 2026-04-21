# reth-pq-node

Post-quantum Ethereum node definition for the `pq-reth` client.

## Components

### `PqNode`

Implements `NodeTypes` and `Node<N>`:

```rust
impl NodeTypes for PqNode {
    type Primitives = PqPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = PqEngineTypes;
}

impl<N> Node<N> for PqNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        PqPoolBuilder,
        BasicPayloadServiceBuilder<PqPayloadBuilderComponent>,
        PqNetworkBuilder,
        PqExecutorBuilder,
        PqConsensusBuilder,
    >;
    type AddOns = ();  // Phase 4 (RPC) will add PqAddOns
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

### `PqPayloadBuilderComponent`

`PayloadBuilderBuilder` that constructs a `PqPayloadBuilder`. Designed to
be used with `BasicPayloadServiceBuilder`:

```rust
BasicPayloadServiceBuilder::new(PqPayloadBuilderComponent)
```

The payload builder:
- Pulls the best transactions from the pool
- Executes them via `PqEvmConfig` (with ML-DSA precompile)
- Produces `PqBuiltPayload` instances
- No blob handling (PQ transactions never carry blobs)

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
| `Node<N>` impl | Complete |
| `PqPoolBuilder` | Complete |
| `PqEngineTypes` + `PqBuiltPayload` | Complete |
| `PqPayloadBuilderComponent` + `PqPayloadBuilder` | Complete |
| `PqConsensusBuilder` | Complete |
| `PqNetworkBuilder` | Complete |
| `PqExecutorBuilder` | Complete (in `reth-pq-evm`) |
| `PqAddOns` (RPC) | Pending (Phase 4) |

## Re-exports

This crate re-exports key types from `reth-pq-evm`:
- `PqEvmConfig`
- `PqEvmFactory`
- `PqExecutorBuilder`
- `PqReceiptBuilder`
