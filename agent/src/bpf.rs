#[path = "./bpf/aegis.skel.rs"]
#[rustfmt::skip]
pub mod agent_skel;

use crate::config::Config;
use agent_skel::{
    AegisSkel, AegisSkelBuilder,
    types::{session_key, session_val},
};
use anyhow::{Context, Result, anyhow};
use bytemuck::{Pod, Zeroable};
use libbpf_rs::{
    Link, MapCore, MapFlags,
    skel::{OpenSkel, SkelBuilder},
};
use nix::time::{ClockId, clock_gettime};
use std::{fs, path::Path};
use tracing::{debug, error, warn};

// Pin paths
const BPF_FS_PATH: &str = "/sys/fs/bpf/aegis";
const MAP_PIN_PATH: &str = "/sys/fs/bpf/aegis/session";
const LINK_PIN_PATH: &str = "/sys/fs/bpf/aegis/xdp_link";

/// BPF program manager - handles loading and interacting with the XDP firewall..
pub struct Bpf<'a> {
    skel: AegisSkel<'a>,
    _link: Link,
}

unsafe impl Zeroable for session_key {}
unsafe impl Pod for session_key {}

unsafe impl Zeroable for session_val {}
unsafe impl Pod for session_val {}

impl<'a> Bpf<'a> {
    /// Creates a new BPF instance and attaches it to the specified interface.
    pub fn new(interface_index: i32, config: &Config) -> Result<Self> {
        if !Path::new(BPF_FS_PATH).exists() {
            fs::create_dir_all(BPF_FS_PATH).context("Failed to create BPF FS directory")?;
        }

        let skel_builder = AegisSkelBuilder::default();

        // Open the BPF skeleton with static lifetime
        let open_object = Box::new_uninit();
        let open_object_ref = Box::leak(open_object);
        let mut open_skel = skel_builder.open(open_object_ref)?;
        open_skel.maps.session.set_pin_path(MAP_PIN_PATH)?;

        // Configure BPF global variables before loading
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("rodata not memory-mapped"))?;

        rodata.CONTROLLER_PORT = config.controller_port.to_be();
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        debug!("BPF configuration applied");

        // Load program into kernel
        let skel = open_skel.load().map_err(|e| {
            error!("Failed to load BPF program: {}", e);
            e
        })?;
        debug!("BPF program loaded into kernel");

        if Path::new(LINK_PIN_PATH).exists() {
            let _ = fs::remove_file(LINK_PIN_PATH);
        }

        // Attach XDP program to interface
        debug!("Attaching XDP to interface {}", interface_index);
        let mut link = skel
            .progs
            .xdp_drop_prog
            .attach_xdp(interface_index)
            .context("Failed to attach XDP program")?;

        link.pin(LINK_PIN_PATH).context("Failed to pin XDP link")?;

        Ok(Self { skel, _link: link })
    }

    /// Adds a firewall rule to allow traffic for a specific session.
    pub fn add_rule(&self, dest_ip: u32, src_ip: u32, dest_port: u16) -> Result<()> {
        let now = Self::get_ktime_ns();

        let key = session_key {
            dest_ip,
            src_ip,
            dest_port,
        };
        let val = session_val {
            created_at_ns: now,
            last_seen_ns: now,
        };

        self.skel.maps.session.update(
            bytemuck::bytes_of(&key),
            bytemuck::bytes_of(&val),
            MapFlags::ANY,
        )?;
        Ok(())
    }

    /// Removes a firewall rule from the map.
    pub fn remove_rule(&self, dest_ip: u32, src_ip: u32, dest_port: u16) -> Result<()> {
        let key = session_key {
            dest_ip,
            src_ip,
            dest_port,
        };
        self.skel
            .maps
            .session
            .delete(bytemuck::bytes_of(&key))
            .map_err(|e| anyhow!(e))
    }

    /// Removes all stale firewall rules from the map.
    /// Returns the number of rules cleaned up.
    pub fn cleanup_ebpf_rules(&self, timeout_ns: u64) -> Result<usize> {
        let now = Self::get_ktime_ns();

        let stale_keys: Vec<Vec<u8>> = self
            .skel
            .maps
            .session
            .keys()
            .filter(|key_bytes| {
                // Safely check value size before accessing
                if let Ok(Some(val_bytes)) = self.skel.maps.session.lookup(key_bytes, MapFlags::ANY)
                {
                    // Validate size to prevent out-of-bounds access
                    if val_bytes.len() != std::mem::size_of::<session_val>() {
                        warn!(
                            "Invalid session value size: {}, expected {}",
                            val_bytes.len(),
                            std::mem::size_of::<session_val>()
                        );
                        return false;
                    }

                    // Check alignment before converting
                    if !(val_bytes.as_ptr() as usize)
                        .is_multiple_of(std::mem::align_of::<session_val>())
                    {
                        warn!("Misaligned session value, skipping");
                        return false;
                    }

                    let val: &session_val = bytemuck::from_bytes(&val_bytes);
                    now.saturating_sub(val.last_seen_ns) > timeout_ns
                } else {
                    false
                }
            })
            .collect();

        let count = stale_keys.len();

        if count > 0 {
            let flat_keys: Vec<u8> = stale_keys.concat();

            // Validate that we have the right amount of data
            if flat_keys.len() != count * std::mem::size_of::<session_key>() {
                return Err(anyhow!("Key data size mismatch during cleanup"));
            }

            // Validate that we have the right amount of data
            if flat_keys.len() != count * std::mem::size_of::<session_key>() {
                return Err(anyhow!("Key data size mismatch during cleanup"));
            }

            self.skel.maps.session.delete_batch(
                &flat_keys,
                count as u32,
                MapFlags::ANY,
                MapFlags::ANY,
            )?;

            debug!("Reaped {} stale session rules", count);
        }

        Ok(count)
    }

    /// Lists all active sessions with their remaining time.
    /// Returns a vector of (src_ip, dest_ip, dest_port, time_left_sec).
    pub fn list_rules(&self, timeout_ns: u64) -> Result<Vec<(u32, u32, u16, i32)>> {
        let now = Self::get_ktime_ns();
        let sessions = self
            .skel
            .maps
            .session
            .keys()
            .filter_map(|key_bytes| {
                // Validate sizes before accessing to prevent out-of-bounds reads
                if key_bytes.len() != std::mem::size_of::<session_key>() {
                    warn!(
                        "Invalid session key size: {}, expected {}",
                        key_bytes.len(),
                        std::mem::size_of::<session_key>()
                    );
                    return None;
                }

                // Validate alignment for session_key
                if !(key_bytes.as_ptr() as usize)
                    .is_multiple_of(std::mem::align_of::<session_key>())
                {
                    warn!("Misaligned session key, skipping");
                    return None;
                }

                if let Ok(Some(val_bytes)) =
                    self.skel.maps.session.lookup(&key_bytes, MapFlags::ANY)
                {
                    // Validate value size
                    if val_bytes.len() != std::mem::size_of::<session_val>() {
                        warn!(
                            "Invalid session value size: {}, expected {}",
                            val_bytes.len(),
                            std::mem::size_of::<session_val>()
                        );
                        return None;
                    }

                    // Validate alignment for session_val
                    if !(val_bytes.as_ptr() as usize)
                        .is_multiple_of(std::mem::align_of::<session_val>())
                    {
                        warn!("Misaligned session value, skipping");
                        return None;
                    }

                    let key: &session_key = bytemuck::from_bytes(&key_bytes);
                    let val: &session_val = bytemuck::from_bytes(&val_bytes);
                    let elapsed = now.saturating_sub(val.last_seen_ns);
                    let time_left_ns = timeout_ns.saturating_sub(elapsed);
                    let time_left_sec = (time_left_ns / 1_000_000_000) as i32;

                    Some((key.src_ip, key.dest_ip, key.dest_port, time_left_sec))
                } else {
                    None
                }
            })
            .collect();
        Ok(sessions)
    }

    /// Returns the current kernel monotonic time in nanoseconds.
    /// Uses a fallback value if the system call fails to prevent panic.
    fn get_ktime_ns() -> u64 {
        match clock_gettime(ClockId::CLOCK_MONOTONIC) {
            Ok(now) => {
                // Safely compute nanoseconds with overflow protection
                now.tv_sec()
                    .saturating_mul(1_000_000_000)
                    .saturating_add(now.tv_nsec()) as u64
            }
            Err(e) => {
                error!("Failed to get monotonic time: {}, using fallback", e);
                // Return a fallback value to prevent panic
                0
            }
        }
    }
}
