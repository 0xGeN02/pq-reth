//! PoA block import for multi-node consensus.
//!
//! In PoA mode without `--dev`, reth's default `NetworkMode::Stake` rejects
//! `NewBlock` messages from peers (EIP-3675). We switch to `NetworkMode::Work`
//! and provide a custom [`BlockImport`] that captures peer blocks and forwards
//! them to the consensus engine.
//!
//! ## Architecture
//!
//! ```text
//! P2P peer  ──NewBlock──▶  PoaBlockImport  ──channel──▶  PoaBlockForwarder
//!                              (sync)                        (async task)
//!                                                               │
//!                                                    engine_newPayload(block)
//!                                                    engine_forkchoiceUpdated()
//!                                                               │
//!                                                               ▼
//!                                                      Engine Tree (validate + import)
//! ```
//!
//! The [`PoaBlockImport`] is wired into the network manager via
//! [`NetworkConfigBuilder::block_import`]. When a peer sends a `NewBlock`,
//! the import handler pushes it through an unbounded channel. The
//! [`PoaBlockForwarder`] task (spawned after launch) reads from the channel
//! and submits each block to the engine via `newPayload` + `forkchoiceUpdated`.

use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, U128};
use alloy_rpc_types_engine::ForkchoiceState;
use reth_engine_primitives::{ConsensusEngineEvent, ConsensusEngineHandle};
use reth_eth_wire_types::NewBlock;
use reth_network::NetworkHandle;
use reth_network::import::{BlockImport, BlockImportEvent, NewBlockEvent};
use reth_network_peers::PeerId;
use reth_payload_primitives::{EngineApiMessageVersion, PayloadTypes};
use reth_primitives_traits::SealedBlock;
use reth_pq_node_primitives::PqPrimitives;
use reth_tokio_util::EventStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::PqEngineTypes;

/// The concrete block type used by PQ network primitives.
pub type PqBlock = <PqPrimitives as reth_node_api::NodePrimitives>::Block;

/// The `NewBlock` payload type propagated over P2P.
pub type PqNewBlock = NewBlock<PqBlock>;

// ─── Peer Block Channel ──────────────────────────────────────────────────────

/// Message sent from [`PoaBlockImport`] to [`PoaBlockForwarder`].
#[derive(Debug)]
pub struct PeerBlockMsg {
    /// The block hash (from the P2P announcement).
    pub hash: B256,
    /// The full block.
    pub block: PqBlock,
}

/// Global storage for the peer block receiver.
///
/// Created during network construction ([`create_peer_block_channel`]),
/// consumed after node launch ([`take_peer_block_receiver`]).
static PEER_BLOCK_RX: OnceLock<Mutex<Option<mpsc::UnboundedReceiver<PeerBlockMsg>>>> =
    OnceLock::new();

/// Take the peer block receiver. Can only be called once; subsequent calls
/// return `None`.
pub fn take_peer_block_receiver() -> Option<mpsc::UnboundedReceiver<PeerBlockMsg>> {
    PEER_BLOCK_RX
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
}

/// Create the peer block channel and store the receiver globally.
///
/// Returns the sender for use in [`PoaBlockImport`].
pub fn create_peer_block_channel() -> mpsc::UnboundedSender<PeerBlockMsg> {
    let (tx, rx) = mpsc::unbounded_channel();
    PEER_BLOCK_RX.get_or_init(|| Mutex::new(Some(rx)));
    tx
}

// ─── PoaBlockImport ──────────────────────────────────────────────────────────

/// Block import handler for PoA consensus.
///
/// Captures `NewBlock` messages from P2P peers and sends them through a
/// channel to the [`PoaBlockForwarder`] for engine import.
///
/// This replaces reth's default [`ProofOfStakeBlockImport`] (which is a no-op)
/// to enable block propagation in PoA networks.
pub struct PoaBlockImport {
    tx: mpsc::UnboundedSender<PeerBlockMsg>,
}

impl PoaBlockImport {
    /// Create a new `PoaBlockImport` with the given channel sender.
    pub fn new(tx: mpsc::UnboundedSender<PeerBlockMsg>) -> Self {
        Self { tx }
    }
}

impl fmt::Debug for PoaBlockImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoaBlockImport").finish()
    }
}

impl BlockImport<PqNewBlock> for PoaBlockImport {
    fn on_new_block(&mut self, peer_id: PeerId, incoming_block: NewBlockEvent<PqNewBlock>) {
        match incoming_block {
            NewBlockEvent::Block(msg) => {
                debug!(
                    target: "pq-reth::poa",
                    hash = %msg.hash,
                    %peer_id,
                    "Received new block from peer, forwarding to engine"
                );
                // Clone the block out of Arc<NewBlock<PqBlock>>
                let block = msg.block.block.clone();
                if self
                    .tx
                    .send(PeerBlockMsg {
                        hash: msg.hash,
                        block,
                    })
                    .is_err()
                {
                    warn!(target: "pq-reth::poa", "Peer block channel closed");
                }
            }
            NewBlockEvent::Hashes(hashes) => {
                debug!(
                    target: "pq-reth::poa",
                    count = hashes.0.len(),
                    "Received block hash announcements from peer (not yet handled)"
                );
                // NewBlockHashes only contain hash + number — we'd need to
                // download the full block. For a 3-validator PoA network,
                // NewBlock (full block) is always sent to sqrt(N) peers,
                // so all peers receive it directly.
            }
        }
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<BlockImportEvent<PqNewBlock>> {
        // We don't emit import events back to the network manager.
        // Block validation happens in the engine (via newPayload).
        // Re-announcement is not needed for small PoA networks.
        Poll::Pending
    }
}

// ─── PoaBlockForwarder ───────────────────────────────────────────────────────

/// Async task that forwards peer blocks to the consensus engine.
///
/// Spawned after node launch with access to the [`ConsensusEngineHandle`].
/// Reads blocks from the channel populated by [`PoaBlockImport`] and submits
/// each one via `engine_newPayload` + `engine_forkchoiceUpdated`.
pub struct PoaBlockForwarder {
    rx: mpsc::UnboundedReceiver<PeerBlockMsg>,
    to_engine: ConsensusEngineHandle<PqEngineTypes>,
    /// Shared chain tip — updated after successful peer block import
    /// to keep `PoaMiningStream` in sync.
    chain_tip: Arc<AtomicU64>,
}

impl fmt::Debug for PoaBlockForwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoaBlockForwarder").finish()
    }
}

impl PoaBlockForwarder {
    /// Create a new `PoaBlockForwarder`.
    pub fn new(
        rx: mpsc::UnboundedReceiver<PeerBlockMsg>,
        to_engine: ConsensusEngineHandle<PqEngineTypes>,
        chain_tip: Arc<AtomicU64>,
    ) -> Self {
        Self { rx, to_engine, chain_tip }
    }

    /// Run the forwarder loop. Blocks until the channel is closed.
    pub async fn run(mut self) {
        info!(target: "pq-reth::poa", "PoA block forwarder started — importing peer blocks via engine");
        while let Some(msg) = self.rx.recv().await {
            self.import_block(msg).await;
        }
        warn!(target: "pq-reth::poa", "PoA block forwarder channel closed, stopping");
    }

    /// Import a single block from a peer.
    async fn import_block(&self, msg: PeerBlockMsg) {
        let hash = msg.hash;
        let block_number = msg.block.header.number();

        // Seal the block (recompute block hash for verification)
        let sealed = SealedBlock::seal_slow(msg.block);
        let computed_hash = sealed.hash();

        if computed_hash != hash {
            warn!(
                target: "pq-reth::poa",
                announced = %hash,
                computed = %computed_hash,
                "Block hash mismatch — using computed hash"
            );
        }

        // Convert to ExecutionData for the engine
        let data = PqEngineTypes::block_to_payload(sealed);

        // Submit via engine_newPayload
        match self.to_engine.new_payload(data).await {
            Ok(status) => {
                if status.is_valid() {
                    debug!(target: "pq-reth::poa", %computed_hash, block_number, "Peer block accepted by engine");

                    // Advance the canonical head to this block
                    let fcu = ForkchoiceState {
                        head_block_hash: computed_hash,
                        safe_block_hash: computed_hash,
                        finalized_block_hash: computed_hash,
                    };
                    match self
                        .to_engine
                        .fork_choice_updated(fcu, None, EngineApiMessageVersion::default())
                        .await
                    {
                        Ok(res) => {
                            if res.is_valid() {
                                // Update shared chain tip so PoaMiningStream
                                // sees the new head on its next tick.
                                self.chain_tip.fetch_max(block_number, Ordering::Release);
                                info!(
                                    target: "pq-reth::poa",
                                    %computed_hash,
                                    block_number,
                                    "Peer block imported as canonical head"
                                );
                            } else {
                                warn!(
                                    target: "pq-reth::poa",
                                    %computed_hash,
                                    ?res,
                                    "FCU for peer block returned non-valid status"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                target: "pq-reth::poa",
                                %computed_hash,
                                ?e,
                                "FCU for peer block failed"
                            );
                        }
                    }
                } else {
                    warn!(
                        target: "pq-reth::poa",
                        %computed_hash,
                        ?status,
                        "Peer block rejected by engine (invalid payload)"
                    );
                }
            }
            Err(e) => {
                error!(
                    target: "pq-reth::poa",
                    %computed_hash,
                    ?e,
                    "engine_newPayload failed for peer block"
                );
            }
        }
    }
}

// ─── PoaBlockAnnouncer ───────────────────────────────────────────────────────

/// Async task that announces locally-produced blocks to P2P peers.
///
/// In PoA mode, `LocalMiner` produces blocks via the engine API (newPayload +
/// FCU). The engine tree commits them as canonical, emitting
/// `CanonicalChainCommitted` events. However, reth does NOT automatically
/// announce engine-committed blocks to P2P peers (by design — in PoS, the
/// CL handles propagation).
///
/// This announcer bridges that gap: it listens for `CanonicalChainCommitted`
/// events and calls `NetworkHandle::announce_block()` to propagate the block
/// to connected peers via `NewBlock` messages.
///
/// Generic over `N: NetworkPrimitives` to avoid coupling to a specific pool type.
pub struct PoaBlockAnnouncer<N: reth_eth_wire_types::NetworkPrimitives> {
    /// Engine event stream — yields `ConsensusEngineEvent` for each canonical update.
    engine_events: EventStream<ConsensusEngineEvent<PqPrimitives>>,
    /// Network handle for announcing blocks to peers.
    network: NetworkHandle<N>,
    /// Provider for reading blocks from the DB.
    provider: Box<dyn BlockProvider>,
}

impl<N: reth_eth_wire_types::NetworkPrimitives> fmt::Debug for PoaBlockAnnouncer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoaBlockAnnouncer").finish()
    }
}

/// Trait for reading blocks from the provider (type-erased).
pub trait BlockProvider: Send + Sync + 'static {
    /// Read a block by hash from the database.
    fn block_by_hash(&self, hash: B256) -> Option<PqBlock>;
}

impl<N> PoaBlockAnnouncer<N>
where
    N: reth_eth_wire_types::NetworkPrimitives<Block = PqBlock, NewBlockPayload = PqNewBlock>,
{
    /// Create a new block announcer.
    pub fn new(
        engine_events: EventStream<ConsensusEngineEvent<PqPrimitives>>,
        network: NetworkHandle<N>,
        provider: Box<dyn BlockProvider>,
    ) -> Self {
        Self { engine_events, network, provider }
    }

    /// Run the announcer loop.
    pub async fn run(mut self) {
        info!(target: "pq-reth::poa", "PoA block announcer started — propagating local blocks to peers");
        while let Some(event) = self.engine_events.next().await {
            if let ConsensusEngineEvent::CanonicalChainCommitted(header, _elapsed) = event {
                let hash = header.hash();
                let number = header.number();

                // Read the full block from the provider
                if let Some(block) = self.provider.block_by_hash(hash) {
                    let new_block = NewBlock {
                        block,
                        td: U128::ZERO, // TD is irrelevant for PoA
                    };
                    self.network.announce_block(new_block, hash);
                    debug!(
                        target: "pq-reth::poa",
                        %hash,
                        number,
                        "Announced canonical block to P2P peers"
                    );
                } else {
                    warn!(
                        target: "pq-reth::poa",
                        %hash,
                        number,
                        "Canonical block committed but not found in DB — cannot announce"
                    );
                }
            }
        }
        warn!(target: "pq-reth::poa", "PoA block announcer event stream closed");
    }
}
