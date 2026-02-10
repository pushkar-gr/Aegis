use anyhow::{Context, Result};
use std::net::ToSocketAddrs;
use tracing::info;

/// Resolve hostname and get IP
pub fn hostname_to_ip(hostname: String) -> Result<std::net::Ipv4Addr> {
    let socket_str = format!("{}:0", hostname);
    info!("Resolving address: {}", socket_str);

    // Resolve hostname to IPv4
    let ipv4 = socket_str
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve host: {}", hostname))?
        .find(|addr| addr.is_ipv4())
        .map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .ok_or_else(|| anyhow::anyhow!("hostname did not resolve to an IPv4 address"))?;

    info!("Resolved {} to {}", hostname, ipv4);
    Ok(ipv4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_resolve_localhost() {
        // Localhost should resolve to 127.0.0.1
        let ip = hostname_to_ip("localhost".to_string()).expect("Failed to resolve localhost");
        assert!(ip.is_loopback());
    }

    #[test]
    fn test_resolve_ip_string() {
        // Passing IP string should work
        let ip = hostname_to_ip("192.168.1.1".to_string()).expect("Failed to parse IP string");
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_resolve_invalid_host() {
        // Using a invalid TLD should fail
        let result = hostname_to_ip("invalid.host.arglebargle".to_string());
        assert!(result.is_err());
    }
}
