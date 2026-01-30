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
use tracing::{debug, error};

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
        let skel_builder = AegisSkelBuilder::default();

        // Open the BPF skeleton with static lifetime
        let open_object = Box::new_uninit();
        let open_object_ref = Box::leak(open_object);
        let mut open_skel = skel_builder.open(open_object_ref)?;

        // Configure BPF global variables before loading
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("rodata not memory-mapped"))?;

        rodata.CONTROLLER_PORT = config.controller_port;
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        debug!("BPF configuration applied");

        // Load program into kernel
        let skel = open_skel.load().map_err(|e| {
            error!("Failed to load BPF program: {}", e);
            e
        })?;
        debug!("BPF program loaded into kernel");

        // Attach XDP program to interface
        debug!("Attaching XDP to interface {}", interface_index);
        let _link = skel
            .progs
            .xdp_drop_prog
            .attach_xdp(interface_index)
            .context("Failed to attach XDP program")?;

        Ok(Self { skel, _link })
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

    /// Removes all ideal firewall rules from the map.
    pub fn cleanup_ebpf_rules(&self, timeout_ns: u64) -> Result<Vec<Vec<u8>>> {
        let now = Self::get_ktime_ns();

        let stale_keys: Vec<Vec<u8>> = self
            .skel
            .maps
            .session
            .keys()
            .filter(|key_bytes| {
                if let Ok(Some(val_bytes)) =
                    self.skel.maps.session.lookup(&key_bytes, MapFlags::ANY)
                {
                    if val_bytes.len() != std::mem::size_of::<session_val>() {
                        return false;
                    }
                    let val: &session_val = bytemuck::from_bytes(&val_bytes);
                    println!(
                        "lastseen: {:?}, time: {:?}, removing: {:?}",
                        val.last_seen_ns,
                        now.saturating_sub(val.last_seen_ns),
                        now.saturating_sub(val.last_seen_ns) > timeout_ns
                    );
                    now.saturating_sub(val.last_seen_ns) > timeout_ns
                } else {
                    false
                }
            })
            .collect();

        let count = stale_keys.len();

        if count > 0 {
            let flat_keys: Vec<u8> = stale_keys.concat();

            self.skel.maps.session.delete_batch(
                &flat_keys,
                count as u32,
                MapFlags::ANY,
                MapFlags::ANY,
            )?;

            debug!("Reaped {} stale session rules", count);
        }
        Ok(stale_keys)
    }

    fn get_ktime_ns() -> u64 {
        let now = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("Failed to get time");
        (now.tv_sec() as u64) * 1_000_000_000 + (now.tv_nsec() as u64)
    }
}
