# reth-pq-primitives

Base types for the post-quantum `pq-reth` Ethereum client.

Replaces ECDSA/secp256k1 with **ML-DSA-65** (CRYSTALS-Dilithium, NIST FIPS 204)
for transaction signing and verification.

## Types

| Type | Description |
|------|-------------|
| `PqTransactionRequest` | Unsigned PQ transaction fields |
| `PqSignedTransaction` | Signed transaction + ML-DSA-65 signature + public key |
| `PqTxType` | Transaction type marker (`0x04`), implements `Typed2718` |
| `PqSignature` | ML-DSA-65 signature — 3309 bytes |
| `PqPublicKey` | ML-DSA-65 verifying key — 1952 bytes |
| `PqSigner` | Keypair generation and signing |

## Modules

| Module | Contents |
|--------|----------|
| `transaction` | Core types: `PqTransactionRequest`, `PqSignedTransaction`, `PqTxType` |
| `signature` | `PqPublicKey`, `PqSignature`, ML-DSA verify wrapper |
| `signer` | `PqSigner` — keypair generation and signing |
| `signed_tx_impl` | `Transaction`, `SignedTransaction`, `TransactionEnvelope` trait impls |
| `rlp` | RLP encoding/decoding (`Encodable`, `Decodable`, EIP-2718) |
| `compact` | `Compact` codec for DB storage |
| `tx_env` | `FromRecoveredTx<PqSignedTransaction>` and `FromTxWithEncoded` for `TxEnv` |
| `error` | `PqError` type |

## Trait Implementations on `PqSignedTransaction`

- `Encodable` / `Decodable` (alloy-rlp)
- `Encodable2718` / `Decodable2718` (alloy-eips)
- `Typed2718` / `IsTyped2718` (alloy-eips)
- `SignerRecoverable` (alloy-consensus)
- `Transaction` / `TransactionEnvelope` (alloy-consensus)
- `TxHashRef` (alloy-consensus)
- `InMemorySize` / `SignedTransaction` (reth-primitives-traits)
- `Compact` to/from (reth-codecs)
- `FromRecoveredTx` / `FromTxWithEncoded` → `TxEnv` (alloy-evm)

## Tests

```bash
cargo test -p reth-pq-primitives   # 10 tests
```
