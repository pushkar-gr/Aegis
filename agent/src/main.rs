//! # Aegis Agent
//!
//! User-space loader for the Aegis eBPF firewall.
//!
//! Responsibilities:
//! - Load and attach XDP program to network interface
//! - Parse configuration from command-line arguments
//! - Run gRPC server for session management
//!
//! ## Usage
//!
//! ```sh
//! sudo ./aegis-agent -i eth0 -c 192.168.1.5 -p 8080
//! ```

mod bpf;
mod cap;
mod config;
mod grpc_server;

use crate::{bpf::Bpf, config::Config, grpc_server::start_grpc_server};
use anyhow::{Context, Result};
use nix::net::if_::if_nametoindex;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Main entry point - initializes the agent and starts serving requests.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Aegis Agent starting...");

    // Verify we have necessary privileges
    debug!("Checking capabilities...");
    cap::check_capabilities().with_context(|| "Missing required capabilities")?;
    info!("Capabilities verified");

    // Load configuration
    let args: Vec<String> = env::args().collect();
    let config = Config::load(&args)?;
    debug!("Configuration: {:?}", config);

    // Resolve network interface
    let interface_index = if_nametoindex(config.iface_name)
        .with_context(|| format!("Interface '{}' not found", config.iface_name))?
        as i32;

    info!(
        "Interface: {} (index: {})",
        config.iface_name, interface_index
    );

    // Load and attach BPF program
    debug!("Loading XDP program...");
    let bpf = Arc::new(std::sync::Mutex::new(Bpf::new(interface_index, &config)?));
    info!("XDP program attached");

    // Show active policy
    warn!("Zero-trust policy active on {}", config.iface_name);
    warn!(
        "Allowing only controller traffic ({}:{}) and authorized sessions",
        config.controller_ip, config.controller_port
    );

    let bpf_cleanup = bpf.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            debug!("Running periodic eBPF rule cleanup...");
            match bpf_cleanup.lock() {
                Ok(bpf) => {
                    if let Err(e) = bpf.cleanup_ebpf_rules(60000000000) {
                        error!("Failed to cleanup stale rules: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to acquire BPF lock for cleanup: {}", e);
                }
            }
        }
    });

    // Start gRPC server
    let server_addr = SocketAddr::from(([0, 0, 0, 0], 50001));
    info!("Starting gRPC server on {}", server_addr);

    let bpf_grpc = bpf.clone();
    let modify_rule_handler = Arc::new(Mutex::new(
        move |is_add: bool, dest_ip: u32, src_ip: u32, dest_port: u16| -> Result<()> {
            let bpf = bpf_grpc
                .lock()
                .map_err(|_| anyhow::anyhow!("BPF mutex poisoned"))?;

            if is_add {
                bpf.add_rule(dest_ip.to_be(), src_ip.to_be(), dest_port)
            } else {
                bpf.remove_rule(dest_ip.to_be(), src_ip.to_be(), dest_port)
            }
        },
    ));

    start_grpc_server(
        server_addr,
        config.controller_ip,
        modify_rule_handler,
        &config.cert_file,
        &config.key_file,
        &config.ca_file,
    )
    .await?;

    Ok(())
}
