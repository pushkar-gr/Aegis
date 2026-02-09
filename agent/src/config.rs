use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{debug, warn};

use crate::hostname_to_ip::hostname_to_ip;

/// Agent configuration loaded from command-line arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct Config<'a> {
    /// Network interface to attach XDP program to
    pub iface_name: &'a str,
    /// Controller IP address
    pub controller_ip: Ipv4Addr,
    /// Controller port number
    pub controller_port: u16,
    /// Delay before updating session timestamp (nanoseconds)
    pub lazy_update_timeout: u64,
    /// TLS certificate paths
    pub cert_file: String,
    pub key_file: String,
    pub ca_file: String,
    /// Rule timeout in nanoseconds before cleanup
    pub rule_timeout_ns: u64,
    /// Cleanup interval in seconds
    pub cleanup_interval_sec: u64,
    /// Broadcast channel size for monitoring
    pub broadcast_channel_size: usize,
    /// gRPC server port
    pub grpc_server_port: u16,
}

impl<'a> Default for Config<'a> {
    fn default() -> Self {
        Self {
            iface_name: "eth0",
            controller_ip: Ipv4Addr::new(172, 21, 0, 5),
            controller_port: 443,
            lazy_update_timeout: 1_000_000_000, // 1s
            cert_file: "certs/agent.pem".to_string(),
            key_file: "certs/agent.key".to_string(),
            ca_file: "certs/ca.pem".to_string(),
            rule_timeout_ns: 60_000_000_000, // 60s
            cleanup_interval_sec: 30,
            broadcast_channel_size: 16,
            grpc_server_port: 50001,
        }
    }
}

impl<'a> Config<'a> {
    /// Parses configuration from command-line arguments.
    ///
    /// Returns the loaded configuration or an error if parsing fails.
    pub fn load(args: &'a [String]) -> Result<Self> {
        let mut config = Self::default();

        // Start at index 1 to skip the binary name
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                // Interface name
                "-i" | "--iface" => {
                    if i + 1 < args.len() {
                        config.iface_name = &args[i + 1];
                        i += 1;
                    }
                }

                // Controller IP
                "-c" | "--ip" => {
                    if i + 1 < args.len() {
                        let ip_str = &args[i + 1];
                        config.controller_ip = Ipv4Addr::from_str(ip_str)
                            .with_context(|| format!("Invalid IPv4 address: {}", ip_str))?;
                        i += 1;
                    }
                }

                // Controller host
                "--host" => {
                    if i + 1 < args.len() {
                        config.controller_ip = hostname_to_ip(args[i + 1].clone())?;
                        i += 1;
                    }
                }

                // Controller port
                "-p" | "--port" => {
                    if i + 1 < args.len() {
                        let port_str = &args[i + 1];
                        config.controller_port = port_str
                            .parse::<u16>()
                            .with_context(|| format!("Invalid port number: {}", port_str))?;
                        i += 1;
                    }
                }

                // Session update timeout
                "-n" | "--update-time" => {
                    if i + 1 < args.len() {
                        let time_str = &args[i + 1];
                        config.lazy_update_timeout = time_str
                            .parse::<u64>()
                            .with_context(|| format!("Invalid update-time: {}", time_str))?;
                        i += 1;
                    }
                }

                "--cert-pem" => {
                    if i + 1 < args.len() {
                        let certs_path = &args[i + 1];
                        config.cert_file = certs_path.to_string();
                    }
                }

                "--cert-key" => {
                    if i + 1 < args.len() {
                        let certs_path = &args[i + 1];
                        config.key_file = certs_path.to_string();
                    }
                }
                "--cert-ca" => {
                    if i + 1 < args.len() {
                        let certs_path = &args[i + 1];
                        config.ca_file = certs_path.to_string();
                    }
                }

                // Rule timeout in nanoseconds
                "-r" | "--rule-timeout" => {
                    if i + 1 < args.len() {
                        let timeout_str = &args[i + 1];
                        config.rule_timeout_ns = timeout_str
                            .parse::<u64>()
                            .with_context(|| format!("Invalid rule-timeout: {}", timeout_str))?;
                        i += 1;
                    }
                }

                // Cleanup interval in seconds
                "--cleanup-interval" => {
                    if i + 1 < args.len() {
                        let interval_str = &args[i + 1];
                        config.cleanup_interval_sec =
                            interval_str.parse::<u64>().with_context(|| {
                                format!("Invalid cleanup-interval: {}", interval_str)
                            })?;
                        i += 1;
                    }
                }

                // Broadcast channel size
                "--channel-size" => {
                    if i + 1 < args.len() {
                        let size_str = &args[i + 1];
                        config.broadcast_channel_size = size_str
                            .parse::<usize>()
                            .with_context(|| format!("Invalid channel-size: {}", size_str))?;
                        i += 1;
                    }
                }

                // gRPC server port
                "-g" | "--grpc-port" => {
                    if i + 1 < args.len() {
                        let port_str = &args[i + 1];
                        config.grpc_server_port = port_str
                            .parse::<u16>()
                            .with_context(|| format!("Invalid grpc-port: {}", port_str))?;
                        i += 1;
                    }
                }

                // Help
                "-h" | "--help" => {
                    Self::print_help();
                }

                // Unknown argument
                _ => {
                    warn!("Unknown argument '{}' - ignoring", args[i]);
                }
            }
            i += 1;
        }

        debug!("Configuration loaded: {:?}", config);
        Ok(config)
    }

    /// Prints usage information and exits.
    fn print_help() {
        println!("Aegis Agent - Zero Trust Network Firewall");
        println!("\nUsage: aegis-agent [OPTIONS]");
        println!("\nOptions:");
        println!("  -i, --iface <NAME>          Network interface (default: eth0)");
        println!("  -c, --ip <IP>               Controller IP (default: 172.21.0.5)");
        println!(
            "  --host <IP>                 Controller hostname (automically resolves hostname and uses as controller ip)"
        );
        println!("  -p, --port <PORT>           Controller port (default: 443)");
        println!(
            "  -n, --update-time <NS>      Session update timeout in ns (default: 1000000000)"
        );
        println!("  -r, --rule-timeout <NS>     Rule timeout in ns (default: 60000000000)");
        println!("  -g, --grpc-port <PORT>      gRPC server port (default: 50001)");
        println!("  --cleanup-interval <SEC>    Cleanup interval in seconds (default: 30)");
        println!("  --channel-size <SIZE>       Broadcast channel size (default: 16)");
        println!("  --cert-pem <FILE>           Certificate file (default: certs/agent.pem)");
        println!("  --cert-key <FILE>           Private key file (default: certs/agent.key)");
        println!("  --cert-ca <FILE>            CA certificate (default: certs/ca.pem)");
        println!("  -h, --help                  Show this help message");
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_defaults() {
        let args = vec!["program_name".to_string()];
        let config = Config::load(&args).expect("Failed to load default config");

        assert_eq!(config.iface_name, "eth0");
        assert_eq!(config.controller_ip, Ipv4Addr::new(172, 21, 0, 5));
        assert_eq!(config.controller_port, 443);
    }

    #[test]
    fn test_load_custom_values() {
        let args = vec![
            "aegis".to_string(),
            "--iface".to_string(),
            "docker0".to_string(),
            "--ip".to_string(),
            "10.0.0.1".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load custom config");

        assert_eq!(config.iface_name, "docker0");
        assert_eq!(config.controller_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.controller_port, 8080);
    }

    #[test]
    fn test_load_short_flags() {
        let args = vec![
            "aegis".to_string(),
            "-i".to_string(),
            "eth1".to_string(),
            "-c".to_string(),
            "192.168.1.1".to_string(),
            "-p".to_string(),
            "9090".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load short flags");

        assert_eq!(config.iface_name, "eth1");
        assert_eq!(config.controller_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.controller_port, 9090);
    }

    #[test]
    fn test_invalid_ip_format() {
        let args = vec![
            "aegis".to_string(),
            "--ip".to_string(),
            "999.999.999.999".to_string(),
        ];
        let result = Config::load(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_port_format() {
        let args = vec![
            "aegis".to_string(),
            "--port".to_string(),
            "invalid_port".to_string(),
        ];
        let result = Config::load(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_paths() {
        let args = vec![
            "aegis".to_string(),
            "--cert-pem".to_string(),
            "/custom/cert.pem".to_string(),
            "--cert-key".to_string(),
            "/custom/key.pem".to_string(),
            "--cert-ca".to_string(),
            "/custom/ca.pem".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load cert paths");

        assert_eq!(config.cert_file, "/custom/cert.pem");
        assert_eq!(config.key_file, "/custom/key.pem");
        assert_eq!(config.ca_file, "/custom/ca.pem");
    }

    #[test]
    fn test_update_timeout() {
        let args = vec![
            "aegis".to_string(),
            "-n".to_string(),
            "5000000000".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load update timeout");

        assert_eq!(config.lazy_update_timeout, 5000000000);
    }

    #[test]
    fn test_mixed_flags() {
        let args = vec![
            "aegis".to_string(),
            "-i".to_string(),
            "eth2".to_string(),
            "--ip".to_string(),
            "10.1.1.1".to_string(),
            "-p".to_string(),
            "8443".to_string(),
            "--update-time".to_string(),
            "2000000000".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load mixed flags");

        assert_eq!(config.iface_name, "eth2");
        assert_eq!(config.controller_ip, Ipv4Addr::new(10, 1, 1, 1));
        assert_eq!(config.controller_port, 8443);
        assert_eq!(config.lazy_update_timeout, 2000000000);
    }

    #[test]
    fn test_invalid_update_timeout() {
        let args = vec![
            "aegis".to_string(),
            "--update-time".to_string(),
            "not_a_number".to_string(),
        ];
        let result = Config::load(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_args_ignored() {
        let args = vec![
            "aegis".to_string(),
            "--unknown-flag".to_string(),
            "value".to_string(),
            "-i".to_string(),
            "eth0".to_string(),
        ];
        // Should not panic, just log a warning
        let config = Config::load(&args).expect("Should handle unknown args");
        assert_eq!(config.iface_name, "eth0");
    }

    #[test]
    fn test_load_hostname_flag() {
        let args = vec![
            "aegis".to_string(),
            "--host".to_string(),
            "localhost".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to resolve localhost via flag");

        // Localhost should resolve to 127.0.0.1
        assert_eq!(config.controller_ip, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_host_override() {
        let args = vec![
            "aegis".to_string(),
            "--ip".to_string(),
            "1.1.1.1".to_string(),
            "--host".to_string(),
            "localhost".to_string(),
        ];
        let config = Config::load(&args).expect("Failed to load config");

        // Should use the localhost IP (127.0.0.1), overriding 1.1.1.1
        assert_eq!(config.controller_ip, Ipv4Addr::new(127, 0, 0, 1));
    }
}
