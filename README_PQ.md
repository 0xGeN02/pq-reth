# pq-reth — Migración Post-Cuántica del Cliente Ethereum

Fork del cliente Ethereum [Reth](https://github.com/paradigmxyz/reth) extendido
con criptografía post-cuántica completa. Añade soporte nativo para transacciones
firmadas con **ML-DSA-65 (CRYSTALS-Dilithium)** sin modificar ningún crate
upstream de Reth.

---

## Filosofía de diseño

- **Sin modificar código upstream.** Todos los cambios viven bajo
  `crates/pq/` como crates nuevos dentro del workspace de Reth.
- **Tipo de transacción `0x04`.** No colisiona con los tipos existentes
  (`0x00` legacy, `0x01` EIP-2930, `0x02` EIP-1559, `0x03` EIP-4844).
- **La clave pública viaja en la transacción.** ML-DSA no es recuperable como
  ECDSA, así que el campo `public_key` forma parte del payload firmado.
- **Derivación de address idéntica a ECDSA.** `address = keccak256(pk_bytes)[12..]`.

---

## Mapa de crates

```
pq-reth/crates/pq/
├── reth-pq-primitives/    ← tipos base: PqSignedTransaction, PqSigner, RLP
├── reth-pq-consensus/     ← validación de transacciones PQ
├── reth-pq-precompile/    ← precompile ML-DSA verify en dirección 0x0100
├── reth-pq-pool/          ← integración con el mempool de Reth
└── reth-pq-evm/           ← EVM factory con el precompile registrado
```

---

## reth-pq-primitives

El crate base. Define todos los tipos que el resto del stack necesita.

### Tipos principales

#### `PqTransactionRequest`
Campos de una transacción PQ sin firmar:

```rust
pub struct PqTransactionRequest {
    pub nonce:     u64,
    pub to:        Option<Address>,  // None = contract creation
    pub value:     u128,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub input:     Vec<u8>,
    pub chain_id:  u64,
}
```

#### `PqSignedTransaction`
Transacción firmada. Incluye firma y clave pública:

```rust
pub struct PqSignedTransaction {
    pub tx:         PqTransactionRequest,
    pub signature:  PqSignature,    // 3309 bytes — ML-DSA-65
    pub public_key: PqPublicKey,    // 1952 bytes — ML-DSA-65
    pub hash:       B256,           // keccak256 del encoding completo
}
```

#### `PqSigner`
Genera keypairs y firma transacciones:

```rust
let signer = PqSigner::generate();
let signed_tx = signer.sign_transaction(tx_request);
let address = signer.address();
```

### Encoding EIP-2718

Las transacciones PQ se codifican como:

```
0x04 || RLP([nonce, to, value, gas_limit, gas_price, input, chain_id,
             signature_bytes, public_key_bytes])
```

El campo `hash` de `PqSignedTransaction` es público para que el pool y otros
componentes puedan referenciarlo directamente.

### Traits implementados

`PqSignedTransaction` implementa todos los traits que Reth espera de una
transacción de primera clase:

| Trait | Módulo |
|---|---|
| `Encodable` / `Decodable` | `alloy-rlp` |
| `Encodable2718` / `Decodable2718` | `alloy-eips` |
| `Typed2718` / `IsTyped2718` | `alloy-eips` |
| `SignerRecoverable` | `alloy-consensus` |
| `Transaction` | `alloy-consensus` |
| `TxHashRef` | `alloy-consensus` |
| `InMemorySize` | `reth-primitives-traits` |
| `SignedTransaction` | `reth-primitives-traits` |

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

Conecta el precompile ML-DSA con la máquina virtual.

### `PqEvmFactory`

Implementa `EvmFactory` de `alloy-evm`. Construye EVMs con el conjunto de
precompiles de Prague **más** el precompile ML-DSA-65 en `0x0100`:

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

### `PqExecutorBuilder`

Conecta `PqEvmFactory` con el node builder de Reth:

```rust
NodeBuilder::new(node_config)
    .with_types::<EthereumNode>()
    .with_components(
        EthereumNode::components()
            .executor(PqExecutorBuilder::default())
    )
    .with_add_ons(EthereumAddOns::default())
    .launch()
    .await?;
```

### `PqEvmConfig`

Alias de tipo para `EthEvmConfig<ChainSpec, PqEvmFactory>`.

---

## Ejecutar todos los tests PQ

```bash
cd pq-reth
cargo test -p reth-pq-primitives \
           -p reth-pq-consensus  \
           -p reth-pq-precompile \
           -p reth-pq-pool
```

Resultado esperado: **~24 tests, 0 fallos**.

---

## Flujo completo de una transacción PQ

```
pq-wallet CLI
    │
    │  PqTxRequest → PqSigner.sign() → PqSignedTransaction (0x04)
    │
    ▼
eth_sendRawTransaction (JSON-RPC)
    │
    ▼
reth-pq-pool
    │  PqPoolValidator: gas_limit, gas_price, ML-DSA verify
    ▼
Mempool
    │
    ▼
Block builder
    │  PqTransactionValidator (reth-pq-consensus)
    ▼
reth-pq-evm  (PqEvmFactory)
    │  EVM ejecuta la transacción
    │  Si el contrato llama a 0x0100 → precompile ML-DSA verify
    ▼
Bloque confirmado
```

---

## Notas de compatibilidad

- Las transacciones `0x04` solo son reconocidas por nodos que tengan
  `PqEvmFactory` activado. Un nodo Reth estándar las rechazará como tipo
  desconocido.
- El precompile en `0x0100` es transparente para contratos que no lo llamen:
  ningún bloque legacy se ve afectado.
- Este es un **prototipo de investigación**. No usar con fondos reales.
