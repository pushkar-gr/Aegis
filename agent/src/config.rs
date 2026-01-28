use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{debug, warn};

/// Configuration for the Aegis Agent.
///
/// Holds the configuration loaded from command line arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct Config<'a> {
    /// The network interface to attach the XDP program to.
    pub iface_name: &'a str,
    /// The IP address of the remote controller.
    pub controller_ip: Ipv4Addr,
    /// The port number of the remote controller.
    pub controller_port: u16,
    /// Time before re updating last_seen_ns in session_val (ns).
    pub lazy_update_timeout: u64,
    /// agent sertificates
    pub cert_file: String,
    pub key_file: String,
    pub ca_file: String,
}

impl<'a> Default for Config<'a> {
    fn default() -> Self {
        Self {
            iface_name: "eth0",
            controller_ip: Ipv4Addr::new(172, 21, 0, 5),
            controller_port: 443,
            lazy_update_timeout: 1000000000, // 1s
            cert_file: "certs/agent.pem".to_string(),
            key_file: "certs/agent.key".to_string(),
            ca_file: "certs/ca.pem".to_string(),
        }
    }
}

impl<'a> Config<'a> {
    /// Loads configuration from command-line arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - A slice of strings representing command line arguments.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `Config` struct if parsing is successful,
    /// or an error if invalid IP addresses or ports are provided.
    pub fn load(args: &'a [String]) -> Result<Self> {
        let mut config = Self::default();

        // Start at index 1 to skip the binary name
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                // Parse Interface Name
                "-i" | "--iface" => {
                    if i + 1 < args.len() {
                        config.iface_name = &args[i + 1];
                        i += 1;
                    }
                }

                // Parse Controller IP
                "-c" | "--ip" => {
                    if i + 1 < args.len() {
                        let ip_str = &args[i + 1];
                        config.controller_ip = Ipv4Addr::from_str(ip_str)
                            .with_context(|| format!("Invalid IPv4 address: {}", ip_str))?;
                        i += 1;
                    }
                }

                // Parse Controller Port
                "-p" | "--port" => {
                    if i + 1 < args.len() {
                        let port_str = &args[i + 1];
                        config.controller_port = port_str
                            .parse::<u16>()
                            .with_context(|| format!("Invalid port number: {}", port_str))?;
                        i += 1;
                    }
                }

                // Parse Lazy Update Time
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

                // Handle unknown arguments or help
                "-h" | "--help" => {
                    Self::print_help();
                }

                _ => {
                    warn!("Unknown argument '{}' detected and ignored.", args[i]);
                }
            }
            i += 1;
        }

        debug!("Configuration loaded successfully: {:?}", config);
        Ok(config)
    }

    /// Prints the help message and exits the program.
    fn print_help() {
        println!("Usage: program [OPTIONS]");
        println!("Options:");
        println!("  -i, --iface <NAME>          Set interface name (default: eth0)");
        println!("  -c, --ip <IP>               Set controller IP (default: 172.21.0.5)");
        println!("  -p, --port <PORT>           Set controller port (default: 443)");
        println!("  -n, --update-time <TIME>    Set update-time (default: 1000000000ns)");
        println!("  --cert-pem <FILE>           Set cert_file (default: certs/agent.pem)");
        println!("  --cert-key <FILE>           Set key_file (default: certs/agent.key)");
        println!("  --cert-ca <FILE>            Set ca_file (default: certs/ca.pem)");
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
}
