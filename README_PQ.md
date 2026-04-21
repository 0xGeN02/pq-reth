# pq-reth — Post-Quantum Ethereum Client Migration

Fork of the [Reth](https://github.com/paradigmxyz/reth) Ethereum client with
**complete post-quantum cryptography**. Replaces ECDSA/secp256k1 entirely with
**ML-DSA-65 (CRYSTALS-Dilithium)** for transaction signing and **ML-KEM (Kyber)**
for key encapsulation. No backward compatibility with classic transactions.

---

## Migration Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | NodePrimitives (`PqPrimitives`) | **Complete** |
| 2 | DB Compact codec | **Complete** |
| 3 | Block execution (EVM config, receipt builder, node types) | **Complete** (core) |
| 4 | RPC layer | Pending |
| 5 | P2P networking | Pending |
| 6 | Sender recovery | Pending |
| 7 | Deprecate ecrecover | Pending |

---

## Design Philosophy

- **No upstream modifications.** All changes live under `crates/pq/` as new
  crates within the Reth workspace.
- **Total replacement, no backward compatibility.** Classic ECDSA transactions
  are not supported. This simplifies the design significantly.
- **Transaction type `0x04`.** Collides with EIP-7702 on Ethereum mainnet but
  is acceptable since we don't support classic tx types.
- **Public key in the transaction.** ML-DSA is not recoverable like ECDSA, so
  the `public_key` field is part of the signed payload.
- **Address derivation identical to ECDSA.** `address = keccak256(pk_bytes)[12..]`.

---

## Crate Map

```
pq-reth/crates/pq/
├── reth-pq-primitives/       ← base types: PqSignedTransaction, PqSigner, RLP, Compact, TxEnv
├── reth-pq-consensus/        ← PQ transaction validation
├── reth-pq-precompile/       ← ML-DSA verify precompile at 0x0100
├── reth-pq-pool/             ← mempool integration
├── reth-pq-evm/              ← PqEvmFactory, PqEvmConfig, PqReceiptBuilder, PqExecutorBuilder
├── reth-pq-node-primitives/  ← PqPrimitives (NodePrimitives impl)
└── reth-pq-node/             ← PqNode (NodeTypes), consensus/network builders
```

---

## reth-pq-primitives

The base crate. Defines all types that the rest of the stack needs.

### Core Types

#### `PqTransactionRequest`
Unsigned PQ transaction fields:

```rust
pub struct PqTransactionRequest {
    pub nonce:     u64,
    pub to:        Option<Address>,  // None = contract creation
    pub value:     u128,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub input:     Bytes,            // alloy_primitives::Bytes
    pub chain_id:  u64,
}
```

#### `PqSignedTransaction`
Signed transaction with ML-DSA-65 signature and public key:

```rust
pub struct PqSignedTransaction {
    pub tx:         PqTransactionRequest,
    pub signature:  PqSignature,    // 3309 bytes — ML-DSA-65
    pub public_key: PqPublicKey,    // 1952 bytes — ML-DSA-65
    pub hash:       B256,           // keccak256 of the full signed encoding
}
```

#### `PqTxType`
Transaction type marker implementing `Typed2718`. Used as
`<PqSignedTransaction as TransactionEnvelope>::TxType`. Always returns
`PQ_TX_TYPE = 0x04`.

#### `PqSigner`
Generates ML-DSA-65 keypairs and signs transactions:

```rust
let signer = PqSigner::generate();
let signed_tx = signer.sign_transaction(tx_request);
let address = signer.address();
```

### Encoding EIP-2718

PQ transactions encode as:

```
0x04 || RLP([nonce, to, value, gas_limit, gas_price, input, chain_id,
             signature_bytes, public_key_bytes])
```

The `hash` field of `PqSignedTransaction` is public so the pool and other
components can reference it directly.

### Traits Implemented

`PqSignedTransaction` implements all traits Reth expects from a first-class
transaction type:

| Trait | Source |
|---|---|
| `Encodable` / `Decodable` | `alloy-rlp` |
| `Encodable2718` / `Decodable2718` | `alloy-eips` |
| `Typed2718` / `IsTyped2718` | `alloy-eips` |
| `SignerRecoverable` | `alloy-consensus` |
| `Transaction` | `alloy-consensus` |
| `TransactionEnvelope` | `alloy-consensus` |
| `TxHashRef` | `alloy-consensus` |
| `InMemorySize` | `reth-primitives-traits` |
| `SignedTransaction` | `reth-primitives-traits` |
| `Compact` (to/from) | `reth-codecs` |
| `FromRecoveredTx` / `FromTxWithEncoded` → `TxEnv` | `alloy-evm` |

### TxEnv Mapping (`tx_env.rs`)

`FromRecoveredTx<PqSignedTransaction> for TxEnv` lives in this crate (orphan
rules — `PqSignedTransaction` must be local). Maps all PQ fields to revm's
`TxEnv`:
- `nonce`, `gas_limit`, `gas_price` → direct mapping
- `to` → `TxKind::Call` or `TxKind::Create`
- `input` → `tx_env.data`
- `value` → `U256::from(value)`
- Caller derived from `recover_signer()`

### Tests (10/10)

```bash
cargo test -p reth-pq-primitives
```

---

## reth-pq-consensus

Validación estática de transacciones PQ antes de que entren al mempool o sean
incluidas en bloques.

### `PqTransactionValidator`

Verifica:
1. `chain_id` correcto (replay protection)
2. `gas_limit > 0`
3. `gas_price > 0`
4. Firma ML-DSA-65 válida contra la clave pública embebida

```rust
let validator = PqTransactionValidator::new(chain_id);
validator.validate(&signed_tx)?;
```

### Tests (4/4 + 1 doctest)

```bash
cargo test -p reth-pq-consensus
```

---

## reth-pq-precompile

Precompile EVM que expone la verificación ML-DSA-65 a contratos Solidity.

### Dirección

```
0x0000000000000000000000000000000000000100
```

Elegida por encima de `0x11` (última dirección de BLS12-381 / EIP-2537) para
evitar colisiones con cualquier precompile estándar actual o futuro.

### Input (5293 bytes)

```
[ msg_hash  :   32 bytes ]  keccak256 del mensaje firmado
[ signature : 3309 bytes ]  firma ML-DSA-65 en bruto
[ public_key: 1952 bytes ]  clave verificadora ML-DSA-65 en bruto
```

### Output

```
0x01  → firma válida
0x00  → firma inválida o input malformado (nunca revierte)
```

### Gas

50 000 gas fijo (ajustable con benchmarks). Refleja que una verificación
ML-DSA-65 tarda ~40ms vs ~3 000 gas para `ecrecover`.

### Uso desde Solidity

```solidity
function pqVerify(
    bytes32 msgHash,
    bytes calldata signature,  // 3309 bytes
    bytes calldata publicKey   // 1952 bytes
) internal view returns (bool) {
    bytes memory input = abi.encodePacked(msgHash, signature, publicKey);
    (bool ok, bytes memory result) = address(0x0100).staticcall(input);
    return ok && result.length == 1 && result[0] == 0x01;
}
```

### Tests (5/5)

```bash
cargo test -p reth-pq-precompile
```

---

## reth-pq-pool

Integración de transacciones PQ con el mempool de Reth.

### `PqPooledTransaction`

Envuelve `Recovered<PqSignedTransaction>` (transacción + dirección del remitente
ya recuperada) y pre-calcula los campos que el pool necesita para ordenar:

- `cost = gas_price × gas_limit + value`
- `encoded_length` — longitud EIP-2718 en bytes

Implementa `PoolTransaction` y `EthPoolTransaction`. Las operaciones blob
(EIP-4844) devuelven `None` / `Ok(())` porque las transacciones PQ no tienen
sidecar.

### `PqPoolValidator`

Implementa `TransactionValidator` para el pool:

1. `gas_limit > 0`
2. `gas_price > 0`
3. Firma ML-DSA-65 válida

```rust
// En el arranque del nodo:
let pool = Pool::new(
    PqPoolValidator,
    KakarotOrdering::default(),
    PoolConfig::default(),
);
```

> **Nota:** La versión actual reporta `balance = U256::MAX` y el `nonce` de la
> propia transacción como estado de la cuenta. Una implementación de producción
> consultaría el `StateProvider` para obtener los valores reales.

---

## reth-pq-evm

Full EVM configuration for post-quantum block execution.

### `PqEvmFactory`

Implements `EvmFactory` from `alloy-evm`. Builds EVMs with Prague precompiles
**plus** the ML-DSA-65 precompile at `0x0100`:

```rust
pub fn pq_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let mut precompiles = Precompiles::prague().clone();
        precompiles.extend([Precompile::new(
            PrecompileId::custom("ml-dsa-65"),
            MLDSA_VERIFY_ADDRESS,  // 0x0100
            ml_dsa_verify,
        )]);
        precompiles
    })
}
```

### `PqReceiptBuilder`

Implements `ReceiptBuilder<Transaction=PqSignedTransaction, Receipt=Receipt>`.
Maps PQ transactions to `TxType::Eip7702` (byte 0x04) in alloy's receipt
format — acceptable because we don't support classic Ethereum tx types.

### `PqEvmConfig`

Full `ConfigureEvm` implementation with `Primitives = PqPrimitives`. **Not** a
type alias — it's a standalone struct that wraps:
- `EthBlockExecutorFactory<PqReceiptBuilder, Arc<C>, PqEvmFactory>` — block
  execution
- `EthBlockAssembler<C>` — block assembly (generic, reused from Ethereum)

```rust
let evm_config = PqEvmConfig::new(chain_spec);
// evm_config.block_executor_factory() → ready for block execution
// evm_config.block_assembler()        → ready for block assembly
```

### `PqExecutorBuilder`

Wires `PqEvmConfig` into the node builder. Requires
`Primitives = PqPrimitives` on the node type:

```rust
impl<Node> ExecutorBuilder<Node> for PqExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<
        ChainSpec = ChainSpec,
        Primitives = PqPrimitives,
    >>,
{ ... }
```

---

## reth-pq-node-primitives

Defines `PqPrimitives` — the `NodePrimitives` implementation for the PQ chain.

```rust
pub struct PqPrimitives;

impl NodePrimitives for PqPrimitives {
    type Block = Block<PqSignedTransaction>;
    type BlockHeader = Header;
    type BlockBody = BlockBody<PqSignedTransaction>;
    type SignedTx = PqSignedTransaction;
    type Receipt = Receipt;
}
```

All downstream crates (`reth-pq-evm`, `reth-pq-node`) are parameterized over
`PqPrimitives` instead of `EthPrimitives`.

---

## reth-pq-node

Top-level node definition that wires all PQ components together.

### `PqNode`

Implements `NodeTypes`:

```rust
impl NodeTypes for PqNode {
    type Primitives = PqPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = PqPayloadTypes;
}
```

### `PqPayloadTypes`

Payload types reusing Ethereum payload attributes (signature-agnostic) with
`EthBuiltPayload<PqPrimitives>` for built payloads.

### `PqConsensusBuilder`

Wraps `EthBeaconConsensus` — validates block-level rules (gas, timestamp, etc.)
without depending on transaction signature type.

### `PqNetworkBuilder`

Reuses the standard Ethereum networking stack. P2P protocol is
transaction-type agnostic at this layer.

### Status

- `NodeTypes` impl: **complete**
- `PqExecutorBuilder`: **complete** (in `reth-pq-evm`)
- `PqConsensusBuilder`: **complete**
- `PqNetworkBuilder`: **complete**
- `Node<N>` wiring: **pending** — requires PQ-specific transaction pool and
  payload builder

---

## Running All PQ Tests

```bash
cd pq-reth
cargo test -p reth-pq-primitives \
           -p reth-pq-consensus  \
           -p reth-pq-precompile \
           -p reth-pq-pool
```

Expected result: **~24 tests, 0 failures**.

---

## Complete PQ Transaction Flow

```
pq-wallet CLI
    |
    |  PqTxRequest → PqSigner.sign() → PqSignedTransaction (0x04)
    |
    v
eth_sendRawTransaction (JSON-RPC)
    |
    v
reth-pq-pool
    |  PqPoolValidator: gas_limit, gas_price, ML-DSA verify
    v
Mempool
    |
    v
Block builder
    |  PqTransactionValidator (reth-pq-consensus)
    v
reth-pq-evm  (PqEvmConfig → PqEvmFactory)
    |  PqReceiptBuilder builds receipt
    |  EVM executes the transaction
    |  If contract calls 0x0100 → ML-DSA verify precompile
    v
Block confirmed
```

---

## Key Design Decisions

### `FromRecoveredTx` placement (orphan rules)
`FromRecoveredTx<PqSignedTransaction> for TxEnv` must live in `reth-pq-primitives`
(where `PqSignedTransaction` is local), not in `reth-pq-evm`. Rust's orphan
rule requires at least one local type in the impl.

### `PqEvmConfig` is not a type alias
`EthEvmConfig` hardcodes `type Primitives = EthPrimitives` — it cannot be
reused via type alias. `PqEvmConfig` is a standalone struct with its own
`ConfigureEvm` impl.

### PQ_TX_TYPE = 0x04 maps to TxType::Eip7702
In alloy's enum, `0x04 = TxType::Eip7702`. In receipts, PQ transactions map
to this variant. This is acceptable because we never process classic EIP-7702
transactions.

### ML-DSA is not recoverable
Unlike ECDSA, ML-DSA signatures cannot recover the public key. The public key
is included in every transaction. `recover_signer()` simply derives the
address from the embedded key: `keccak256(pk_bytes)[12..]`.

---

## Compatibility Notes

- PQ transactions (`0x04`) are only recognized by nodes with `PqEvmFactory`
  active. A standard Reth node will reject them as unknown type.
- The precompile at `0x0100` is transparent to contracts that don't call it —
  no legacy block is affected.
- This is a **research prototype**. Do not use with real funds.
