use anyhow::{Result, anyhow};
use caps::{CapSet, Capability};
use tracing::{debug, warn};

/// Required Linux capabilities for XDP operations
const REQUIRED_CAPS: [(Capability, &str); 2] = [
    (Capability::CAP_BPF, "CAP_BPF"),
    (Capability::CAP_NET_ADMIN, "CAP_NET_ADMIN"),
];

/// Verifies the process has necessary Linux capabilities for XDP.
///
/// Returns an error if any required capabilities are missing.
pub fn check_capabilities() -> Result<()> {
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
                return Err(anyhow!("Failed to check {}: {}", name, e));
            }
        }
    }

    if !missing_caps.is_empty() {
        return Err(anyhow!(
            "Missing capabilities: {}. Run with sudo or grant capabilities.",
            missing_caps.join(", ")
        ));
    }

    Ok(())
}
