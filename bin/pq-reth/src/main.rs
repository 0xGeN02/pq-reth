//! # pq-reth
//!
//! Post-Quantum Ethereum execution node.
//!
//! This binary launches a [`PqNode`] — a reth-based Ethereum execution client
//! that replaces ECDSA/secp256k1 with ML-DSA-65 (CRYSTALS-Dilithium) for
//! transaction signing and verification.
//!
//! ## Usage
//!
//! ```bash
//! # Start in dev mode (auto-mining, no consensus layer needed)
//! pq-reth node --dev --dev.block-time 5s --http --http.addr 0.0.0.0
//!
//! # Start with custom chain spec
//! pq-reth node --chain /path/to/pq-genesis.json --http
//! ```

#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use clap::Parser;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_pq_node::PqNode;
use tracing::info;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) =
        reth_ethereum_cli::Cli::<EthereumChainSpecParser>::parse().run(async move |builder, _| {
            info!(target: "pq-reth::cli", "Launching Post-Quantum node (ML-DSA-65)");
            let handle = builder
                .node(PqNode::default())
                .launch_with_debug_capabilities()
                .await?;

            handle.wait_for_node_exit().await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
