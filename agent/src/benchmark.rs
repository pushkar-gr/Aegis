#[cfg(test)]
mod benchmarks {
    use crate::config::Config;
    use libbpf_rs::ProgramInput;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::mem::MaybeUninit;

    #[test]
    #[ignore]
    fn benchmark_xdp_latency() {
        // Setup a dummy config
        let config = Config {
            controller_ip: "127.0.0.1".parse().unwrap(),
            controller_port: 8080,
            ..Default::default()
        };

        // Load the BPF program
        let skel_builder = crate::bpf::agent_skel::AegisSkelBuilder::default();

        let mut open_object = MaybeUninit::uninit();

        let mut open_skel = skel_builder
            .open(&mut open_object)
            .expect("Failed to open skel");

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.CONTROLLER_PORT = config.controller_port;
        rodata.CONTROLLER_IP = u32::from(config.controller_ip).to_be();
        rodata.LAZY_UPDATE_TIMEOUT = config.lazy_update_timeout;

        let skel = open_skel.load().expect("Failed to load");

        // Create a raw IPv4/TCP packet (approx 64 bytes)
        let packet: [u8; 64] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Src MAC
            0x08, 0x00, // EtherType (IPv4)
            0x45, 0x00, 0x00, 0x32, // Version, IHL, TOS, Len
            0x00, 0x00, 0x40, 0x00, // ID, Flags
            0x40, 0x06, 0x00, 0x00, // TTL, Proto (TCP), Checksum
            0x7F, 0x00, 0x00, 0x01, // Src IP (127.0.0.1)
            0x7F, 0x00, 0x00, 0x01, // Dst IP (127.0.0.1)
            0x1F, 0x90, 0x1F, 0x90, // Src Port, Dst Port (8080)
            0x00, 0x00, 0x00, 0x00, // Seq
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Run Benchmark
        let repetitions = 100_000;
        let prog = &skel.progs.xdp_drop_prog;

        let mut test_args = ProgramInput::default();
        test_args.data_in = Some(&packet);
        test_args.repeat = repetitions;

        let result = prog.test_run(test_args).expect("Benchmark failed");

        // Calculate Latency
        let avg_ns = result.duration.as_nanos() as f64;

        println!("---------------------------------------------------");
        println!(" BPF BENCHMARK RESULTS ");
        println!("---------------------------------------------------");
        println!(" Total Runs:     {}", repetitions);
        println!(" Avg Latency:    {:.2} ns/packet", avg_ns);
        println!(" Target:         < 2000 ns");
        println!(
            " Status:         {}",
            if avg_ns < 2000.0 { "PASS" } else { "FAIL" }
        );
        println!("---------------------------------------------------");

        assert!(avg_ns < 2000.0, "Latency too high: {} ns", avg_ns);
    }
}
