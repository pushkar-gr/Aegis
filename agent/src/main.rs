//! # Aegis Agent
//!
//! `aegis-agent` is a user-space loader for the Aegis eBPF XDP program.
//!
//! It is responsible for:
//! 1. Loading the compiled BPF skeleton.
//! 2. Attaching the XDP program to a specified network interface.
//! 3. Managing the lifecycle of the BPF link.
//!
//! ## Usage
//!
//! ```sh
//! sudo ./aegis-agent <interface>
//! ```

#[path = "bpf/aegis.skel.rs"]
mod agent_skel;

use crate::agent_skel::AegisSkelBuilder;
use anyhow::{Context, Result, anyhow};
use caps::{CapSet, Capability};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use nix::net::if_::if_nametoindex;
use std::{env, mem::MaybeUninit, thread, time::Duration};
use tracing::{debug, info, warn};

/// Required capabilities for BPF operations
const REQUIRED_CAPS: [(Capability, &str); 2] = [
    (Capability::CAP_BPF, "CAP_BPF"),
    (Capability::CAP_NET_ADMIN, "CAP_NET_ADMIN"),
];

/// Entry point for the Aegis Agent.
///
/// This function initializes logging, parses CLI arguments for the target interface,
/// loads the XDP BPF program, and attaches it.
///
/// # Arguments
///
/// * `[1]` - (Optional) The name of the network interface to attach to (e.g., "eth0").
///           Defaults to "eth0" if not provided.
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("🛡️ Aegis Agent: Online");

    // Check for required capabilities
    debug!("Checking required capabilities...");
    check_capabilities().context("Capability check failed")?;
    info!("✓ All required capabilities present");

    // Get interface
    let args: Vec<String> = env::args().collect();
    let iface_name = if args.len() > 1 {
        &args[1]
    } else {
        warn!("No interface specified, defaulting to 'eth0'");
        "eth0"
    };
    debug!("Command line arguments: {:?}", args);

    // Resolve interface index
    let ifindex = if_nametoindex(iface_name)
        .with_context(|| format!("Failed to find interface {}", iface_name))?
        as i32;

    info!("Targeting Interface: {} (Index: {})", iface_name, ifindex);

    // Build and load the BPF Skeleton
    debug!("Building BPF skeleton...");
    let skel_builder = AegisSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    debug!("BPF skeleton opened successfully");

    let skel = open_skel.load()?;
    debug!("BPF skeleton loaded into kernel");

    // Attach XDP program
    debug!("Attaching XDP program to interface index {}", ifindex);
    let _link = skel
        .progs
        .xdp_drop_prog
        .attach_xdp(ifindex)
        .context("Failed to attach XDP program")?;
    debug!("XDP program attached successfully");

    info!(
        "BLOCKED: Incoming traffic on {} is now dropped.",
        iface_name
    );
    info!("OPEN: Traffic on other interfaces is unaffected.");

    // Keep the process alive to maintain the BPF link
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Checks if the process has the required Linux capabilities to load and attach BPF programs.
///
/// # Required Capabilities
///
/// * `CAP_BPF` - Required to load BPF programs (Linux 5.8+).
/// * `CAP_NET_ADMIN` - Required to attach XDP programs to network interfaces.
///
/// # Returns
///
/// Returns `Ok(())` if all required capabilities are present, else returns an error.
fn check_capabilities() -> Result<()> {
    let mut missing_caps = Vec::new();

    for (cap, name) in &REQUIRED_CAPS {
        match caps::has_cap(None, CapSet::Effective, *cap) {
            Ok(true) => {
                debug!("Capability check passed: {}", name);
            }
            Ok(false) => {
                missing_caps.push(*name);
            }
            Err(e) => {
                return Err(anyhow!("Failed to check capability {}: {}", name, e));
            }
        }
    }

    if !missing_caps.is_empty() {
        return Err(anyhow!(
            "Missing required capabilities: {}. Please run with sufficient privileges (e.g., sudo).",
            missing_caps.join(", ")
        ));
    }

    Ok(())
}
