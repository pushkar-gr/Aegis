//! # Aegis Agent
//!
//! `aegis-agent` is a user-space loader for the Aegis eBPF XDP program.
//!
//! It is responsible for:
//! 1. Loading the compiled BPF skeleton.
//! 2. Parsing runtime configuration (Interface, Controller IP/Port).
//! 3. Attaching the XDP program to the network interface.
//! 4. Running a gRPC server to accept session management requests from the controller.
//!
//! ## Usage
//!
//! ```sh
//! sudo ./aegis-agent -i eth0 -c 192.168.1.5 -p 8080
//! ```

#[path = "bpf/aegis.skel.rs"]
#[rustfmt::skip]
mod agent_skel;
mod config;
mod grpc_server;

use crate::{
    agent_skel::{
        AegisSkel, AegisSkelBuilder,
        types::{session_key, session_val},
    },
    config::Config,
    grpc_server::start_grpc_server,
};
use anyhow::{Context, Result, anyhow};
use bytemuck::{Pod, Zeroable};
use caps::{CapSet, Capability};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    {MapCore, MapFlags},
};
use nix::net::if_::if_nametoindex;
use std::{
    env,
    mem::MaybeUninit,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

unsafe impl Zeroable for session_key {}
unsafe impl Pod for session_key {}

unsafe impl Zeroable for session_val {}
unsafe impl Pod for session_val {}

/// Required capabilities for BPF operations
const REQUIRED_CAPS: [(Capability, &str); 2] = [
    (Capability::CAP_BPF, "CAP_BPF"),
    (Capability::CAP_NET_ADMIN, "CAP_NET_ADMIN"),
];

/// Entry point for the Aegis Agent.
///
/// This function initializes logging, parses CLI arguments, validates privileges,
/// manages the BPF lifecycle, and starts the gRPC server.
#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize Logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Aegis Agent: Online");

    // 2. Privilege Check
    debug!("Checking required capabilities...");
    check_capabilities().with_context(|| "Capability check failed")?;
    info!("All required capabilities present");

    // 3. Configuration Loading
    let args: Vec<String> = env::args().collect();
    let config = Config::load(&args)?;
    debug!("Config loaded: {:?}", config);

    // 4. Interface Resolution
    let ifindex = if_nametoindex(config.iface_name)
        .with_context(|| format!("Failed to find interface {}", config.iface_name))?
        as i32;

    info!(
        "Target Interface: {} (Index: {})",
        config.iface_name, ifindex
    );

    // 5. BPF Skeleton Lifecycle
    debug!("Building and mapping BPF skeleton...");
    let skel_builder = AegisSkelBuilder::default();

    // Leak open_object upfront to get 'static lifetime
    let open_object_static = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut open_skel = skel_builder.open(open_object_static)?;

    // Map global variables before loading
    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .ok_or_else(|| anyhow!("`rodata` is not memory mapped"))?;

    rodata.CONTROLLER_PORT = config.controller_port;
    rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
    rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

    debug!("BPF skeleton configured successfully");

    // Load into Kernel
    let skel = open_skel.load().map_err(|e| {
        error!("Failed to load BPF program into kernel: {}", e);
        e
    })?;
    debug!("BPF programs loaded into kernel memory");

    // 6. Attach XDP Program
    debug!("Attaching XDP program to interface index {}", ifindex);
    let _link = skel
        .progs
        .xdp_drop_prog
        .attach_xdp(ifindex)
        .context("Failed to attach XDP program")?;

    info!("XDP Program attached successfully");

    // 7. Operational Logging
    warn!("ZERO TRUST POLICY ACTIVE on {}", config.iface_name);
    warn!(
        "DROPPING all incoming traffic NOT destined to Controller ({}:{})",
        config.controller_ip, config.controller_port
    );

    // 8. Start gRPC Server
    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], 50001));
    info!("Preparing to start gRPC server on {}", grpc_addr);

    // Leak skeleton to get 'static reference
    let skel_static: &'static AegisSkel = Box::leak(Box::new(skel));

    let add_rule_fn = Arc::new(Mutex::new(
        move |dest_ip: u32, src_ip: u32, dest_port: u16| -> Result<()> {
            add_rule(skel_static, dest_ip, src_ip, dest_port)
        },
    ));

    // Start the gRPC server
    let _keep_link = _link;
    start_grpc_server(grpc_addr, config.controller_ip, add_rule_fn).await?;

    Ok(())
}

/// Adds a rule to the BPF session map
pub fn add_rule(skel: &AegisSkel, dest_ip: u32, src_ip: u32, dest_port: u16) -> Result<()> {
    let key = session_key {
        dest_ip,
        src_ip,
        dest_port,
    };
    let val = session_val {
        created_at_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos() as u64,
        last_seen_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos() as u64,
    };
    skel.maps.session.update(
        bytemuck::bytes_of(&key),
        bytemuck::bytes_of(&val),
        MapFlags::ANY,
    )?;
    Ok(())
}

/// Checks if the process has the required Linux capabilities.
///
/// XDP requires `CAP_BPF` and `CAP_NET_ADMIN`.
///
/// # Returns
///
/// * `Ok(())` - All capabilities are present.
/// * `Err` - One or more capabilities are missing.
fn check_capabilities() -> Result<()> {
    let mut missing_caps = Vec::new();

    for (cap, name) in &REQUIRED_CAPS {
        match caps::has_cap(None, CapSet::Effective, *cap) {
            Ok(true) => {
                debug!("Has capability: {}", name);
            }
            Ok(false) => {
                warn!("Missing capability: {}", name);
                missing_caps.push(*name);
            }
            Err(e) => {
                return Err(anyhow!(format!(
                    "Failed to check capability {}: {}",
                    name, e
                )));
            }
        }
    }

    if !missing_caps.is_empty() {
        return Err(anyhow!(
            "Missing required capabilities: {}. Please run with sudo.",
            missing_caps.join(", ")
        ));
    }

    Ok(())
}
