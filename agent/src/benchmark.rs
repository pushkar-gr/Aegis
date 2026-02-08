#[cfg(test)]
mod benchmarks {
    use crate::bpf::agent_skel::types::{session_key, session_val};
    use crate::config::Config;
    use bytemuck;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use libbpf_rs::{MapCore, MapFlags, ProgramInput};
    use std::mem::MaybeUninit;
    use std::time::Instant;

    /// Helper function to create a TCP packet with specified source and destination
    fn create_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], dst_port: u16) -> [u8; 64] {
        let mut packet = [0u8; 64];

        // Ethernet header
        packet[12] = 0x08; // EtherType IPv4 (high byte)
        packet[13] = 0x00; // EtherType IPv4 (low byte)

        // IPv4 header
        packet[14] = 0x45; // Version 4, IHL 5
        packet[15] = 0x00; // TOS
        packet[16] = 0x00; // Total length (high)
        packet[17] = 0x32; // Total length (low)
        packet[18] = 0x00; // ID (high)
        packet[19] = 0x00; // ID (low)
        packet[20] = 0x40; // Flags
        packet[21] = 0x00; // Fragment offset
        packet[22] = 0x40; // TTL
        packet[23] = 0x06; // Protocol (TCP)
        packet[24] = 0x00; // Checksum (high)
        packet[25] = 0x00; // Checksum (low)

        // Source IP
        packet[26..30].copy_from_slice(&src_ip);

        // Destination IP
        packet[30..34].copy_from_slice(&dst_ip);

        // TCP header
        packet[34] = 0x1F; // Src port (high) - 8080
        packet[35] = 0x90; // Src port (low)
        packet[36] = (dst_port >> 8) as u8; // Dst port (high)
        packet[37] = (dst_port & 0xFF) as u8; // Dst port (low)

        packet
    }

    /// Helper function to generate a random-looking IP address (deterministic for reproducibility)
    fn generate_ip(seed: u32) -> [u8; 4] {
        // Simple LCG pseudo-random number generator for deterministic IPs
        let a = 1664525u32;
        let c = 1013904223u32;
        let next = a.wrapping_mul(seed).wrapping_add(c);

        [
            ((next >> 24) & 0xFF) as u8,
            ((next >> 16) & 0xFF) as u8,
            ((next >> 8) & 0xFF) as u8,
            (next & 0xFF) as u8,
        ]
    }

    /// Helper to convert u32 IP to bytes
    fn ip_to_bytes(ip: u32) -> [u8; 4] {
        [
            ((ip >> 24) & 0xFF) as u8,
            ((ip >> 16) & 0xFF) as u8,
            ((ip >> 8) & 0xFF) as u8,
            (ip & 0xFF) as u8,
        ]
    }

    /// Helper to fill the session map with entries
    fn fill_session_map(
        skel: &crate::bpf::agent_skel::AegisSkel,
        count: usize,
        base_ip: u32,
        base_port: u16,
    ) {
        for i in 0..count {
            let src_ip = base_ip.wrapping_add(i as u32);
            let dest_ip = base_ip.wrapping_add(10000 + i as u32);
            let dest_port = base_port.wrapping_add((i % 1000) as u16);

            let key = session_key {
                src_ip: src_ip.to_be(),
                dest_ip: dest_ip.to_be(),
                dest_port: dest_port.to_be(),
            };

            let val = session_val {
                created_at_ns: 1000000000,
                last_seen_ns: 1000000000,
            };

            skel.maps
                .session
                .update(
                    bytemuck::bytes_of(&key),
                    bytemuck::bytes_of(&val),
                    MapFlags::ANY,
                )
                .expect("Failed to insert session");
        }

        println!("Pre-filled session map with {} entries", count);
    }

    #[test]
    #[ignore]
    fn benchmark_attack_scenario_dropped_packets() {
        println!("\nBENCHMARK: Attack Scenario (Dropped Packets)");

        let config = Config {
            controller_ip: "172.21.0.5".parse().unwrap(),
            controller_port: 443,
            ..Default::default()
        };

        let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .expect("Failed to open skel");

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.CONTROLLER_PORT = config.controller_port.to_be();
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        let skel = open_skel.load().expect("Failed to load");

        // Fill the map with legitimate sessions
        let map_size = 5000;
        fill_session_map(&skel, map_size, 0x0A000001, 8000); // Base IP: 10.0.0.1

        // Create packets from RANDOM unauthorized IPs (attack traffic)
        let num_unique_packets = 100;
        let repeats_per_packet = 10_000;

        println!(
            " Generating {} unique random packets...",
            num_unique_packets
        );
        let mut packets = Vec::new();
        for i in 0..num_unique_packets {
            let src_ip = generate_ip(i as u32 * 9999);
            let packet = create_tcp_packet(src_ip, [192, 168, 1, 100], 9999);
            packets.push(packet);
        }

        println!(" Map contains {} authorized sessions\n", map_size);
        println!(
            " Running benchmark: {} unique packets x {} repeats each",
            num_unique_packets, repeats_per_packet
        );

        // Benchmark individual packet latency
        let prog = &skel.progs.xdp_drop_prog;
        let mut total_avg_latency = 0.0;

        for packet in &packets {
            let mut test_args = ProgramInput::default();
            test_args.data_in = Some(packet);
            test_args.repeat = repeats_per_packet;

            let result = prog.test_run(test_args).expect("Test run failed");

            // result.duration is the total time for all repeats
            total_avg_latency += result.duration.as_nanos() as f64;

            // Verify packet was dropped (XDP_DROP = 1)
            assert_eq!(result.return_value, 1, "Packet should be dropped");
        }

        // Calculate average latency per packet
        let global_avg_ns = total_avg_latency / num_unique_packets as f64;

        // Measure throughput
        let throughput = 1_000_000_000.0 / global_avg_ns;

        println!(" ATTACK SCENARIO RESULTS");
        println!("  Average Latency:  {:.2} ns/packet", global_avg_ns);
        println!("  Throughput:       {:.0} packets/sec", throughput);
        println!("  Map Size:         {} sessions", map_size);
        println!(
            "  Packets Tested:   {} (all dropped)",
            num_unique_packets * repeats_per_packet
        );
        println!(
            "  Status:           {}",
            if global_avg_ns < 2000.0 {
                "PASS (< 2µs)"
            } else {
                "FAIL"
            }
        );
    }

    #[test]
    #[ignore]
    fn benchmark_legitimate_traffic_accepted_packets() {
        println!("\nBENCHMARK: Legitimate Traffic (Accepted Packets)");

        let config = Config {
            controller_ip: "127.21.0.5".parse().unwrap(),
            controller_port: 443,
            ..Default::default()
        };

        let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .expect("Failed to open skel");

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.CONTROLLER_PORT = config.controller_port.to_be();
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        let skel = open_skel.load().expect("Failed to load");

        // Fill the map with legitimate sessions
        let map_size = 5000;
        let base_ip = 0x0A000001u32; // 10.0.0.1
        fill_session_map(&skel, map_size, base_ip, 8000);

        // Create packets from AUTHORIZED IPs (legitimate traffic)
        let num_unique_packets = 100;
        let repeats_per_packet = 10_000;

        println!(" Generating {} unique valid packets...", num_unique_packets);
        let mut packets = Vec::new();
        for i in 0..num_unique_packets {
            let idx = i % map_size;
            let src_ip = base_ip.wrapping_add(idx as u32);
            let dest_ip = base_ip.wrapping_add(10000 + i as u32);
            let dest_port = 8000 + ((i % 1000) as u16);

            let src_bytes = ip_to_bytes(src_ip);
            let dst_bytes = ip_to_bytes(dest_ip);
            let packet = create_tcp_packet(src_bytes, dst_bytes, dest_port);
            packets.push(packet);
        }

        println!(" Map contains {} authorized sessions\n", map_size);
        println!(
            " Running benchmark: {} unique packets x {} repeats each...",
            num_unique_packets, repeats_per_packet
        );

        // Benchmark individual packet latency
        let prog = &skel.progs.xdp_drop_prog;
        let mut total_avg_latency = 0.0;

        for packet in &packets {
            let mut test_args = ProgramInput::default();
            test_args.data_in = Some(packet);
            test_args.repeat = repeats_per_packet;

            let result = prog.test_run(test_args).expect("Benchmark failed");

            // result.duration is the total time for all repeats
            total_avg_latency += result.duration.as_nanos() as f64;

            // Verify packet was accepted (XDP_PASS = 2)
            assert_eq!(result.return_value, 2, "Packet should be accepted");
        }

        // Calculate average latency per packet
        let global_avg_ns = total_avg_latency / num_unique_packets as f64;

        // Measure throughput
        let throughput = 1_000_000_000.0 / global_avg_ns;

        println!(" LEGITIMATE TRAFFIC RESULTS");
        println!("  Average Latency:  {:.2} ns/packet", global_avg_ns);
        println!("  Throughput:       {:.0} packets/sec", throughput);
        println!("  Map Size:         {} sessions", map_size);
        println!(
            "  Packets Tested:   {} (all accepted)",
            num_unique_packets * repeats_per_packet as usize
        );
        println!(
            "  Status:           {}",
            if global_avg_ns < 2000.0 {
                "PASS (< 2µs)"
            } else {
                "FAIL"
            }
        );
    }

    #[test]
    #[ignore]
    fn benchmark_mixed_traffic() {
        println!("\nBENCHMARK: Mixed Traffic (Attack + Legitimate)");

        let config = Config {
            controller_ip: "172.21.0.5".parse().unwrap(),
            controller_port: 443,
            ..Default::default()
        };

        let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .expect("Failed to open skel");

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.CONTROLLER_PORT = config.controller_port.to_be();
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        let skel = open_skel.load().expect("Failed to load");

        // Fill the map with legitimate sessions
        let map_size = 5000;
        let base_ip = 0x0A000001u32;
        fill_session_map(&skel, map_size, base_ip, 8000);

        let num_unique_packets = 100;
        let repeats_per_packet = 10_000;
        let prog = &skel.progs.xdp_drop_prog;

        let mut total_avg_latency = 0.0;

        println!(
            " Testing with {} packets (50% legitimate, 50% attack)",
            num_unique_packets * repeats_per_packet
        );
        println!(" Map contains {} authorized sessions\n", map_size);

        for i in 0..num_unique_packets {
            let packet;
            let expected_ret;
            let dest_port;
            if i % 2 == 0 {
                // Legitimate traffic (should be accepted)
                let idx = i / 2;
                let src_ip = base_ip.wrapping_add((idx % map_size) as u32);
                let dest_ip = base_ip.wrapping_add(10000 + (idx % map_size) as u32);
                dest_port = 8000 + ((idx % 1000) as u16);

                let src_bytes = ip_to_bytes(src_ip);
                let dst_bytes = ip_to_bytes(dest_ip);
                packet = create_tcp_packet(src_bytes, dst_bytes, dest_port);
                expected_ret = 2; // XDP_PASS
            } else {
                // Attack traffic (should be dropped)
                let random_src = generate_ip((i * 54321) as u32);
                let random_dst = generate_ip((i * 98765) as u32);
                let random_port = 3000 + (i % 5000) as u16;
                packet = create_tcp_packet(random_src, random_dst, random_port);
                expected_ret = 1; // XDP_DROP
            }

            let mut test_args = ProgramInput::default();
            test_args.data_in = Some(&packet);
            test_args.repeat = repeats_per_packet as u32;

            let result = prog.test_run(test_args).expect("Benchmark failed");
            assert_eq!(result.return_value, expected_ret, "Unexpected verdict");

            total_avg_latency += result.duration.as_nanos() as f64;
        }

        // Calculate average latency per packet
        let global_avg_ns = total_avg_latency / num_unique_packets as f64;

        // Measure overall throughput
        let throughput = 1_000_000_000.0 / global_avg_ns;

        println!(" MIXED TRAFFIC RESULTS");
        println!("  Average Latency:  {:.2} ns/packet", global_avg_ns);
        println!("  Throughput:       {:.0} packets/sec", throughput);
        println!("  Map Size:         {} sessions", map_size);
        println!(
            "  Packets Tested:   {}",
            num_unique_packets * repeats_per_packet,
        );
        println!(
            "  Status:           {}",
            if global_avg_ns < 2000.0 {
                "PASS (< 2µs)"
            } else {
                "FAIL"
            }
        );
    }

    #[test]
    #[ignore]
    fn benchmark_map_operations() {
        println!("\nBENCHMARK: eBPF Map Operations Performance");

        let config = Config {
            controller_ip: "172.21.0.5".parse().unwrap(),
            controller_port: 443,
            ..Default::default()
        };

        let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .expect("Failed to open skel");

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.CONTROLLER_PORT = config.controller_port.to_be();
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        let skel = open_skel.load().expect("Failed to load");

        // Benchmark insertions
        let num_ops = 5000;
        let start = Instant::now();

        for i in 0..num_ops {
            let key = session_key {
                src_ip: (0x0A000001u32 + i).to_be(),
                dest_ip: (0x0A010001u32 + i).to_be(),
                dest_port: (8000 + (i % 1000) as u16).to_be(),
            };

            let val = session_val {
                created_at_ns: 1000000000,
                last_seen_ns: 1000000000,
            };

            skel.maps
                .session
                .update(
                    bytemuck::bytes_of(&key),
                    bytemuck::bytes_of(&val),
                    MapFlags::ANY,
                )
                .expect("Failed to insert");
        }

        let insert_elapsed = start.elapsed();
        let insert_throughput = num_ops as f64 / insert_elapsed.as_secs_f64();

        // Benchmark lookups
        let start = Instant::now();

        for i in 0..num_ops {
            let key = session_key {
                src_ip: (0x0A000001u32 + i).to_be(),
                dest_ip: (0x0A010001u32 + i).to_be(),
                dest_port: (8000 + (i % 1000) as u16).to_be(),
            };

            let _result = skel
                .maps
                .session
                .lookup(bytemuck::bytes_of(&key), MapFlags::ANY)
                .expect("Failed to lookup");
        }

        let lookup_elapsed = start.elapsed();
        let lookup_throughput = num_ops as f64 / lookup_elapsed.as_secs_f64();

        // Benchmark deletions
        let start = Instant::now();

        for i in 0..num_ops {
            let key = session_key {
                src_ip: (0x0A000001u32 + i).to_be(),
                dest_ip: (0x0A010001u32 + i).to_be(),
                dest_port: (8000 + (i % 1000) as u16).to_be(),
            };

            let _result = skel.maps.session.delete(bytemuck::bytes_of(&key));
        }

        let delete_elapsed = start.elapsed();
        let delete_throughput = num_ops as f64 / delete_elapsed.as_secs_f64();

        println!(" MAP OPERATIONS RESULTS");
        println!("  Operations:       {} per test", num_ops);
        println!(
            "\n  Insert Latency:   {:.2} µs/op",
            insert_elapsed.as_micros() as f64 / num_ops as f64
        );
        println!("  Insert Throughput: {:.0} ops/sec", insert_throughput);
        println!(
            "\n  Lookup Latency:   {:.2} µs/op",
            lookup_elapsed.as_micros() as f64 / num_ops as f64
        );
        println!("  Lookup Throughput: {:.0} ops/sec", lookup_throughput);
        println!(
            "\n  Delete Latency:   {:.2} µs/op",
            delete_elapsed.as_micros() as f64 / num_ops as f64
        );
        println!("  Delete Throughput: {:.0} ops/sec", delete_throughput);
    }

    #[test]
    #[ignore]
    fn benchmark_scalability_varying_map_sizes() {
        println!("\nBENCHMARK: Scalability with Varying Map Sizes");

        let map_sizes = [100, 500, 1000, 2500, 5000];

        for &size in &map_sizes {
            let config = Config {
                controller_ip: "172.21.0.5".parse().unwrap(),
                controller_port: 443,
                ..Default::default()
            };

            let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();
            let mut open_object = MaybeUninit::uninit();
            let mut open_skel = skel_builder
                .open(&mut open_object)
                .expect("Failed to open skel");

            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.CONTROLLER_PORT = config.controller_port.to_be();
            rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
            rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

            let skel = open_skel.load().expect("Failed to load");

            fill_session_map(&skel, size, 0x0A000001, 8000);

            // Test with legitimate traffic
            let base_ip = 0x0A000001u32;
            let src_bytes = ip_to_bytes(base_ip);
            let dst_bytes = ip_to_bytes(base_ip + 10000);
            let packet = create_tcp_packet(src_bytes, dst_bytes, 8000);

            let prog = &skel.progs.xdp_drop_prog;
            let mut test_args = ProgramInput::default();
            test_args.data_in = Some(&packet);
            test_args.repeat = 100_000;

            let start = Instant::now();
            prog.test_run(test_args).expect("Test run failed");
            let elapsed = start.elapsed();

            let avg_latency_ns = elapsed.as_nanos() as f64 / 100_000.0;
            let throughput = 100_000.0 / elapsed.as_secs_f64();

            println!(
                "  Map Size: {:5} → Latency: {:6.2} ns/pkt | Throughput: {:10.0} pkt/s",
                size, avg_latency_ns, throughput
            );
        }

        println!(" Scalability benchmark complete\n");
    }
}
