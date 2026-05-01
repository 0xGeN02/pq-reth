//! PoA consensus engine: drives block production with round-robin slot rotation.
//!
//! The engine runs as an async task that:
//! 1. Monitors a slot timer (configurable, default 5s)
//! 2. Checks if this node is the current proposer
//! 3. If yes: builds a payload, seals it with ML-DSA-65, broadcasts
//! 4. If no: waits for the next slot

use std::sync::Arc;
use std::time::Duration;

use dilithium::{MlDsa65, SigningKey};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::sealer::seal_header;
use crate::validator::ValidatorSet;

/// Configuration for the PoA engine.
#[derive(Debug, Clone)]
pub struct PoaConfig {
    /// Time between slots (block production interval).
    pub slot_time: Duration,
    /// This node's validator address (20 bytes).
    pub local_address: [u8; 20],
}

impl Default for PoaConfig {
    fn default() -> Self {
        Self {
            slot_time: Duration::from_secs(5),
            local_address: [0u8; 20],
        }
    }
}

/// The PoA consensus engine.
///
/// Drives block production for a set of authorized validators using
/// ML-DSA-65 signatures in round-robin rotation.
#[derive(Debug)]
pub struct PoaEngine {
    /// The authorized validator set.
    validator_set: Arc<ValidatorSet>,
    /// Engine configuration.
    config: PoaConfig,
    /// This node's signing key (None if not a validator).
    signing_key: Option<SigningKey<MlDsa65>>,
    /// Current block number (tracks chain head).
    current_block: u64,
}

impl PoaEngine {
    /// Create a new PoA engine.
    pub fn new(
        validator_set: ValidatorSet,
        config: PoaConfig,
        signing_key: Option<SigningKey<MlDsa65>>,
    ) -> Self {
        Self {
            validator_set: Arc::new(validator_set),
            config,
            signing_key,
            current_block: 0,
        }
    }

    /// Check if this node is the proposer for the given block number.
    pub fn is_local_proposer(&self, block_number: u64) -> bool {
        self.validator_set
            .is_proposer(block_number, &self.config.local_address)
    }

    /// Get the current block number.
    pub fn current_block(&self) -> u64 {
        self.current_block
    }

    /// Advance the block number (called after a block is finalized).
    pub fn advance_block(&mut self) {
        self.current_block += 1;
    }

    /// Seal a block header with this node's ML-DSA-65 key.
    /// Returns None if this node has no signing key.
    pub fn seal(&self, header_bytes: &[u8]) -> Option<Vec<u8>> {
        self.signing_key
            .as_ref()
            .map(|sk| seal_header(sk, header_bytes))
    }

    /// Run the engine loop. This is the main async task that drives consensus.
    ///
    /// The `shutdown` receiver is used to gracefully stop the engine.
    /// The `on_block` callback is invoked when this node should produce a block.
    pub async fn run<F>(&mut self, mut shutdown: watch::Receiver<bool>, mut on_block: F)
    where
        F: FnMut(u64, &[u8]) -> bool, // (block_number, seal) -> success
    {
        info!(
            address = ?hex::encode(self.config.local_address),
            validators = self.validator_set.len(),
            slot_time = ?self.config.slot_time,
            "PoA engine started"
        );

        let mut interval = tokio::time::interval(self.config.slot_time);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let next_block = self.current_block + 1;
                    let proposer = self.validator_set.proposer_at(next_block);

                    if proposer.address == self.config.local_address {
                        debug!(block = next_block, "Our turn to propose");

                        if let Some(ref sk) = self.signing_key {
                            // In a real implementation, we would:
                            // 1. Call engine_getPayload to get the built block
                            // 2. Sign the header
                            // 3. Call engine_newPayload + forkchoiceUpdated
                            //
                            // For now, we produce a placeholder header and seal it.
                            let header_placeholder = next_block.to_be_bytes();
                            let seal = seal_header(sk, &header_placeholder);

                            if on_block(next_block, &seal) {
                                self.current_block = next_block;
                                info!(block = next_block, "Block produced and sealed");
                            } else {
                                warn!(block = next_block, "Block production failed");
                            }
                        } else {
                            warn!("No signing key configured — cannot produce blocks");
                        }
                    } else {
                        debug!(
                            block = next_block,
                            proposer = ?hex::encode(proposer.address),
                            "Not our turn, waiting"
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("PoA engine shutting down");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use dilithium::dilithium65;
    use dilithium::signature::Keypair;

    fn make_test_validator(sk: &SigningKey<MlDsa65>) -> Validator {
        use sha3::{
            Shake256,
            digest::{ExtendableOutput, Update, XofReader},
        };

        let pk_bytes = sk.verifying_key().encode();
        let mut hasher = Shake256::default();
        hasher.update(pk_bytes.as_slice());
        let mut hash = [0u8; 32];
        hasher.finalize_xof().read(&mut hash);

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);

        Validator {
            address,
            public_key: pk_bytes.as_slice().to_vec(),
        }
    }

    #[test]
    fn proposer_rotation() {
        let sk1 = dilithium65::keygen();
        let sk2 = dilithium65::keygen();
        let sk3 = dilithium65::keygen();

        let v1 = make_test_validator(&sk1);
        let v2 = make_test_validator(&sk2);
        let v3 = make_test_validator(&sk3);

        let addr1 = v1.address;

        let vs = ValidatorSet::new(vec![v1, v2, v3]);
        let config = PoaConfig {
            slot_time: Duration::from_secs(5),
            local_address: addr1,
        };

        let engine = PoaEngine::new(vs, config, Some(sk1));

        // Block 0 mod 3 = 0 → validator 0 (us)
        // Block 1 mod 3 = 1 → validator 1
        // Block 2 mod 3 = 2 → validator 2
        // Block 3 mod 3 = 0 → validator 0 (us again)
        assert!(engine.is_local_proposer(0));
        assert!(!engine.is_local_proposer(1));
        assert!(!engine.is_local_proposer(2));
        assert!(engine.is_local_proposer(3));
    }

    #[tokio::test]
    async fn engine_produces_block_on_turn() {
        let sk = dilithium65::keygen();
        let v = make_test_validator(&sk);
        let addr = v.address;

        let vs = ValidatorSet::new(vec![v]);
        let config = PoaConfig {
            slot_time: Duration::from_millis(50),
            local_address: addr,
        };

        let mut engine = PoaEngine::new(vs, config, Some(sk));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut blocks_produced = 0u64;

        // Run engine for a short time, produce 3 blocks, then shutdown
        let handle = tokio::spawn(async move {
            engine
                .run(shutdown_rx, |_block_num, _seal| {
                    blocks_produced += 1;
                    true
                })
                .await;
            blocks_produced
        });

        // Let it run for ~200ms (enough for 3+ blocks at 50ms interval)
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(true);

        let produced = handle.await.unwrap();
        assert!(
            produced >= 2,
            "Should have produced at least 2 blocks, got {produced}"
        );
    }
}
