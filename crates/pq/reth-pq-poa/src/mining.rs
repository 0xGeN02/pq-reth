//! `PoA` mining stream for integration with reth's `MiningMode::Trigger`.
//!
//! Produces a `Stream<Item = ()>` that yields a value only when this node
//! is the proposer for the current slot. This stream is fed into reth's
//! `LocalMiner` which handles all Engine API interaction (payload building,
//! `engine_forkchoiceUpdated`, `engine_newPayload`).
//!
//! ## Design
//!
//! The stream ticks every `slot_time` (e.g. 5 seconds). At each tick:
//! 1. Read the current canonical chain tip from the shared `chain_tip`
//! 2. Compute `next_block = chain_tip + 1`
//! 3. Check if `validators[next_block % len] == local_address`
//! 4. If yes → update `chain_tip` optimistically and yield `()`
//! 5. If no → return `Pending` (wait for next tick)
//!
//! ## Multi-node sync
//!
//! The `chain_tip` is an [`Arc<AtomicU64>`] shared with the
//! [`PoaBlockForwarder`](crate::block_import::PoaBlockForwarder), which
//! updates it when peer blocks are imported. This keeps the proposer
//! rotation in sync with the actual canonical chain state.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Shared canonical chain tip block number. Read on each tick to
    /// determine the next block. Updated by this stream (local blocks,
    /// optimistically) and by `PoaBlockForwarder` (peer blocks).
    chain_tip: Arc<AtomicU64>,
}

impl PoaMiningStream {
    /// Create a new `PoA` mining stream.
    ///
    /// # Arguments
    ///
    /// * `validator_set` - The authorized set of validators
    /// * `local_address` - This node's 20-byte address
    /// * `slot_time` - Time between slots (block production interval)
    /// * `chain_tip` - Shared chain tip, initialized to the current tip
    ///   (typically 0 for a fresh chain). Updated by this stream and
    ///   by `PoaBlockForwarder`.
    pub fn new(
        validator_set: ValidatorSet,
        local_address: [u8; 20],
        slot_time: Duration,
        chain_tip: Arc<AtomicU64>,
    ) -> Self {
        let start = tokio::time::Instant::now() + slot_time;
        let interval = tokio::time::interval_at(start, slot_time);

        let tip = chain_tip.load(Ordering::Relaxed);
        info!(
            address = %hex::encode(local_address),
            validators = validator_set.len(),
            slot_time_ms = slot_time.as_millis(),
            chain_tip = tip,
            "PoA mining stream initialized"
        );

        Self {
            validator_set: Arc::new(validator_set),
            local_address,
            interval,
            chain_tip,
        }
    }
}

impl Stream for PoaMiningStream {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Wait for the next slot tick
        match this.interval.poll_tick(cx) {
            Poll::Ready(_) => {
                let tip = this.chain_tip.load(Ordering::Acquire);
                let next_block = tip + 1;
                let proposer = this.validator_set.proposer_at(next_block);

                if proposer.address == this.local_address {
                    debug!(
                        block = next_block,
                        tip,
                        "PoA: our turn to propose"
                    );
                    // Optimistically advance the chain tip so that the next
                    // tick sees the correct next_block even if the engine
                    // hasn't finished importing yet. If the build fails,
                    // the tip will be corrected by the next peer block or
                    // the next provider read.
                    this.chain_tip.store(next_block, Ordering::Release);
                    return Poll::Ready(Some(()));
                }

                debug!(
                    block = next_block,
                    tip,
                    proposer = %hex::encode(proposer.address),
                    "PoA: not our turn, waiting for peer block"
                );
                // Not our turn — don't advance anything. The chain_tip will
                // be updated by PoaBlockForwarder when the peer's block
                // arrives. Wait for the next tick to re-check.
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
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

        // Use v2 as local so block 1 (1%3=1) is our turn
        let v1 = make_validator(&sk1);
        let v2 = make_validator(&sk2);
        let v3 = make_validator(&sk3);
        let local_addr = v2.address;
        let vs = ValidatorSet::new(vec![v1, v2, v3]);

        let chain_tip = Arc::new(AtomicU64::new(0));
        let mut stream = PoaMiningStream::new(
            vs,
            local_addr,
            Duration::from_millis(10),
            chain_tip.clone(),
        );

        // tip=0, next=1, 1%3=1 → v2 (us!) → should fire
        let _ = stream.next().await;
        // After fire: chain_tip should be 1 (optimistic update)
        assert_eq!(chain_tip.load(Ordering::Relaxed), 1);

        // tip=1, next=2, 2%3=2 → v3, not us → doesn't fire, returns Pending.
        // Simulate peer producing block 2:
        chain_tip.store(2, Ordering::Release);

        // tip=2, next=3, 3%3=0 → v1, not us → Pending.
        // Simulate peer producing block 3:
        chain_tip.store(3, Ordering::Release);

        // tip=3, next=4, 4%3=1 → v2 (us!) → should fire
        let _ = stream.next().await;
        assert_eq!(chain_tip.load(Ordering::Relaxed), 4);
    }
}
