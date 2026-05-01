//! PoA mining stream for integration with reth's `MiningMode::Trigger`.
//!
//! Produces a `Stream<Item = ()>` that yields a value only when this node
//! is the proposer for the current slot. This stream is fed into reth's
//! `LocalMiner` which handles all Engine API interaction (payload building,
//! `engine_forkchoiceUpdated`, `engine_newPayload`).
//!
//! ## Design
//!
//! The stream ticks every `slot_time` (e.g. 5 seconds). At each tick:
//! 1. Compute the current block number (incremented after each successful yield)
//! 2. Check if `validators[block_number % len] == local_address`
//! 3. If yes → yield `()` (triggers block production)
//! 4. If no → skip (wait for next tick)

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use tokio::time::Interval;
use tracing::{debug, info};

use crate::validator::ValidatorSet;

/// A stream that yields `()` only when it's this validator's turn to propose.
///
/// Compatible with `MiningMode::Trigger` from `reth-engine-local`.
#[derive(Debug)]
pub struct PoaMiningStream {
    /// The authorized validator set.
    validator_set: Arc<ValidatorSet>,
    /// This node's validator address (SHAKE-256(pk)[12..32]).
    local_address: [u8; 20],
    /// Slot timer interval.
    interval: Interval,
    /// Next block number to propose.
    next_block: u64,
}

impl PoaMiningStream {
    /// Create a new PoA mining stream.
    ///
    /// # Arguments
    ///
    /// * `validator_set` - The authorized set of validators
    /// * `local_address` - This node's 20-byte address
    /// * `slot_time` - Time between slots (block production interval)
    /// * `start_block` - The next block number to be produced (typically chain tip + 1)
    pub fn new(
        validator_set: ValidatorSet,
        local_address: [u8; 20],
        slot_time: Duration,
        start_block: u64,
    ) -> Self {
        let start = tokio::time::Instant::now() + slot_time;
        let interval = tokio::time::interval_at(start, slot_time);

        info!(
            address = %hex::encode(local_address),
            validators = validator_set.len(),
            slot_time_ms = slot_time.as_millis(),
            start_block,
            "PoA mining stream initialized"
        );

        Self {
            validator_set: Arc::new(validator_set),
            local_address,
            interval,
            next_block: start_block,
        }
    }
}

impl Stream for PoaMiningStream {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Wait for the next slot tick
            match this.interval.poll_tick(cx) {
                Poll::Ready(_) => {
                    let proposer = this.validator_set.proposer_at(this.next_block);

                    if proposer.address == this.local_address {
                        debug!(
                            block = this.next_block,
                            "PoA: our turn to propose"
                        );
                        this.next_block += 1;
                        return Poll::Ready(Some(()));
                    }

                    debug!(
                        block = this.next_block,
                        proposer = %hex::encode(proposer.address),
                        "PoA: not our turn, skipping slot"
                    );
                    // Not our turn — increment block counter and wait for next tick.
                    // Even though we didn't produce, someone else did (or should have).
                    this.next_block += 1;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// Stream never ends (infinite)
impl Unpin for PoaMiningStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use dilithium::dilithium65;
    use dilithium::signature::Keypair;
    use futures_util::StreamExt;
    use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

    fn make_validator(sk: &dilithium::SigningKey<dilithium::MlDsa65>) -> Validator {
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

    #[tokio::test]
    async fn stream_fires_only_on_our_turn() {
        let sk1 = dilithium65::keygen();
        let sk2 = dilithium65::keygen();
        let sk3 = dilithium65::keygen();

        let v1 = make_validator(&sk1);
        let v2 = make_validator(&sk2);
        let v3 = make_validator(&sk3);

        let local_addr = v1.address;
        let vs = ValidatorSet::new(vec![v1, v2, v3]);

        // Start at block 0 with very short slot time for testing
        let mut stream = PoaMiningStream::new(
            vs,
            local_addr,
            Duration::from_millis(10),
            0, // start_block = 0, validator[0] = v1 (us)
        );

        // First fire: block 0 (0 % 3 == 0 → our turn)
        let _ = stream.next().await;
        // After: next_block = 1

        // Second fire: blocks 1,2 skipped, block 3 fires (3 % 3 == 0)
        let _ = stream.next().await;
        // After: next_block = 4

        assert_eq!(stream.next_block, 4);
    }
}
