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
}

impl<'a> Default for Config<'a> {
    fn default() -> Self {
        Self {
            iface_name: "eth0",
            controller_ip: Ipv4Addr::new(172, 21, 0, 5),
            controller_port: 443,
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
        println!("  -i, --iface <NAME>    Set interface name (default: eth0)");
        println!("  -c, --ip <IP>         Set controller IP (default: 172.21.0.5)");
        println!("  -p, --port <PORT>     Set controller port (default: 443)");
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
