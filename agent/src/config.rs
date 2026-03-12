use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{debug, warn};

use crate::hostname_to_ip::hostname_to_ip;

/// Default path for the TOML configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "config.toml";

// TOML file structure
#[derive(Debug, Deserialize)]
#[serde(default)]
struct TomlNetwork {
    iface: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct TomlController {
    ip: String,
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct TomlCerts {
    cert_file: String,
    key_file: String,
    ca_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct TomlSession {
    lazy_update_timeout_ns: u64,
    rule_timeout_ns: u64,
    cleanup_interval_sec: u64,
    broadcast_channel_size: usize,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct TomlGrpc {
    port: u16,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default)]
struct TomlFile {
    network: TomlNetwork,
    controller: TomlController,
    certs: TomlCerts,
    session: TomlSession,
    grpc: TomlGrpc,
}

impl Default for TomlNetwork {
    fn default() -> Self {
        Self {
            iface: "eth0".to_string(),
        }
    }
}

impl Default for TomlController {
    fn default() -> Self {
        Self {
            ip: "172.21.0.5".to_string(),
            host: String::new(),
            port: 443,
        }
    }
}

impl Default for TomlCerts {
    fn default() -> Self {
        Self {
            cert_file: "certs/agent.pem".to_string(),
            key_file: "certs/agent.key".to_string(),
            ca_file: "certs/ca.pem".to_string(),
        }
    }
}

impl Default for TomlSession {
    fn default() -> Self {
        Self {
            lazy_update_timeout_ns: 1_000_000_000,
            rule_timeout_ns: 60_000_000_000,
            cleanup_interval_sec: 30,
            broadcast_channel_size: 16,
        }
    }
}

impl Default for TomlGrpc {
    fn default() -> Self {
        Self { port: 50001 }
    }
}

// impl Default for TomlFile {
//     fn default() -> Self {
//         Self {
//             network: TomlNetwork::default(),
//             controller: TomlController::default(),
//             certs: TomlCerts::default(),
//             session: TomlSession::default(),
//             grpc: TomlGrpc::default(),
//         }
//     }
// }

/// Agent configuration loaded from a TOML file.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// Network interface to attach XDP program to
    pub iface_name: String,
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

impl Default for Config {
    fn default() -> Self {
        let tf = TomlFile::default();
        let controller_ip = Ipv4Addr::from_str(&tf.controller.ip).unwrap();
        Self {
            iface_name: tf.network.iface,
            controller_ip,
            controller_port: tf.controller.port,
            lazy_update_timeout: tf.session.lazy_update_timeout_ns,
            cert_file: tf.certs.cert_file,
            key_file: tf.certs.key_file,
            ca_file: tf.certs.ca_file,
            rule_timeout_ns: tf.session.rule_timeout_ns,
            cleanup_interval_sec: tf.session.cleanup_interval_sec,
            broadcast_channel_size: tf.session.broadcast_channel_size,
            grpc_server_port: tf.grpc.port,
        }
    }
}

impl Config {
    /// Loads configuration from the default `config.toml` path.
    /// If the file does not exist, defaults are used.
    pub fn load() -> Result<Self> {
        Self::load_from_file(DEFAULT_CONFIG_PATH)
    }

    /// Loads configuration from an explicit TOML file path.
    /// If the file does not exist, defaults are used.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let tf: TomlFile = match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config file: {}", path))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("Config file '{}' not found, using built-in defaults", path);
                TomlFile::default()
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to read config file: {}", path));
            }
        };
        Self::from_toml(tf)
    }

    fn from_toml(tf: TomlFile) -> Result<Self> {
        let controller_ip = if !tf.controller.host.is_empty() {
            hostname_to_ip(tf.controller.host.clone())
                .with_context(|| format!("Failed to resolve host: {}", tf.controller.host))?
        } else {
            Ipv4Addr::from_str(&tf.controller.ip)
                .with_context(|| format!("Invalid controller.ip: {}", tf.controller.ip))?
        };

        let config = Self {
            iface_name: tf.network.iface,
            controller_ip,
            controller_port: tf.controller.port,
            lazy_update_timeout: tf.session.lazy_update_timeout_ns,
            cert_file: tf.certs.cert_file,
            key_file: tf.certs.key_file,
            ca_file: tf.certs.ca_file,
            rule_timeout_ns: tf.session.rule_timeout_ns,
            cleanup_interval_sec: tf.session.cleanup_interval_sec,
            broadcast_channel_size: tf.session.broadcast_channel_size,
            grpc_server_port: tf.grpc.port,
        };

        debug!("Configuration loaded: {:?}", config);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("Failed to create temp file");
        f.write_all(content.as_bytes())
            .expect("Failed to write temp file");
        f
    }

    #[test]
    fn test_load_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.iface_name, "eth0");
        assert_eq!(cfg.controller_ip, Ipv4Addr::new(172, 21, 0, 5));
        assert_eq!(cfg.controller_port, 443);
        assert_eq!(cfg.lazy_update_timeout, 1_000_000_000);
        assert_eq!(cfg.grpc_server_port, 50001);
    }

    #[test]
    fn test_load_from_file_defaults() {
        // An empty TOML file should produce the built-in defaults.
        let f = write_toml("");
        let cfg = Config::load_from_file(f.path().to_str().unwrap())
            .expect("Failed to load empty config");

        assert_eq!(cfg.iface_name, "eth0");
        assert_eq!(cfg.controller_ip, Ipv4Addr::new(172, 21, 0, 5));
        assert_eq!(cfg.controller_port, 443);
        assert_eq!(cfg.cert_file, "certs/agent.pem");
        assert_eq!(cfg.grpc_server_port, 50001);
    }

    #[test]
    fn test_load_custom_values() {
        let f = write_toml(
            r#"
[network]
iface = "docker0"

[controller]
ip   = "10.0.0.1"
port = 8080

[certs]
cert_file = "/custom/cert.pem"
key_file  = "/custom/key.pem"
ca_file   = "/custom/ca.pem"

[session]
lazy_update_timeout_ns  = 5_000_000_000
rule_timeout_ns         = 120_000_000_000
cleanup_interval_sec    = 60
broadcast_channel_size  = 32

[grpc]
port = 50002
"#,
        );
        let cfg = Config::load_from_file(f.path().to_str().unwrap())
            .expect("Failed to load custom config");

        assert_eq!(cfg.iface_name, "docker0");
        assert_eq!(cfg.controller_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(cfg.controller_port, 8080);
        assert_eq!(cfg.cert_file, "/custom/cert.pem");
        assert_eq!(cfg.key_file, "/custom/key.pem");
        assert_eq!(cfg.ca_file, "/custom/ca.pem");
        assert_eq!(cfg.lazy_update_timeout, 5_000_000_000);
        assert_eq!(cfg.rule_timeout_ns, 120_000_000_000);
        assert_eq!(cfg.cleanup_interval_sec, 60);
        assert_eq!(cfg.broadcast_channel_size, 32);
        assert_eq!(cfg.grpc_server_port, 50002);
    }

    #[test]
    fn test_missing_file_uses_defaults() {
        let cfg = Config::load_from_file("/nonexistent/path/config.toml")
            .expect("Missing file should fall back to defaults");
        assert_eq!(cfg.iface_name, "eth0");
        assert_eq!(cfg.controller_port, 443);
    }

    #[test]
    fn test_invalid_ip_fails() {
        let f = write_toml(
            r#"
[controller]
ip = "999.999.999.999"
"#,
        );
        let result = Config::load_from_file(f.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_toml_fails() {
        let f = write_toml("{ this is not valid toml");
        let result = Config::load_from_file(f.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_host_resolution() {
        let f = write_toml(
            r#"
[controller]
host = "localhost"
"#,
        );
        let cfg = Config::load_from_file(f.path().to_str().unwrap())
            .expect("Failed to resolve localhost");
        assert_eq!(cfg.controller_ip, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_host_takes_priority_over_ip() {
        let f = write_toml(
            r#"
[controller]
ip   = "1.1.1.1"
host = "localhost"
"#,
        );
        let cfg =
            Config::load_from_file(f.path().to_str().unwrap()).expect("Failed to load config");
        // host should win
        assert_eq!(cfg.controller_ip, Ipv4Addr::new(127, 0, 0, 1));
    }
}
