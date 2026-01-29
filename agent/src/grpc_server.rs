//! # gRPC Server
//!
//! Implements the SessionManager service for the controller to:
//! - Submit session authentication events
//! - Monitor active sessions

// Include the generated protobuf code
pub mod session {
    tonic::include_proto!("session");
}

use anyhow::{Context, Result, anyhow};
use session::{
    Ack, Empty, LoginEvent, SessionList,
    session_manager_server::{SessionManager, SessionManagerServer},
};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};
use tracing::{debug, error, info, warn};

/// Callback function type for adding firewall rules
type AddRuleFn = Arc<Mutex<dyn Fn(u32, u32, u16) -> Result<()> + Send + Sync>>;

/// SessionManager service implementation
pub struct SessionManagerService {
    controller_ip: Ipv4Addr,
    add_rule: AddRuleFn,
}

impl SessionManagerService {
    pub fn new(controller_ip: Ipv4Addr, add_rule: AddRuleFn) -> Self {
        Self {
            controller_ip,
            add_rule,
        }
    }

    /// Verifies the request originates from the authorized controller.
    fn validate_controller_ip(&self, remote_addr: Option<SocketAddr>) -> Result<(), Status> {
        match remote_addr {
            Some(addr) => {
                let ip = match addr.ip() {
                    IpAddr::V4(ipv4) => ipv4,
                    IpAddr::V6(_) => {
                        warn!("Rejected request from IPv6 address: {}", addr.ip());
                        return Err(Status::permission_denied(
                            "Only IPv4 addresses are supported",
                        ));
                    }
                };

                if ip == self.controller_ip {
                    info!("Accepted request from controller: {}", ip);
                    Ok(())
                } else {
                    warn!(
                        "ected unauthorized IP: {} (expected {})",
                        ip, self.controller_ip
                    );
                    Err(Status::permission_denied(
                        "Only controller requests are accepted",
                    ))
                }
            }
            None => {
                warn!("Rejected request - no remote address");
                Err(Status::permission_denied("Cannot determine remote address"))
            }
        }
    }
}

#[tonic::async_trait]
impl SessionManager for SessionManagerService {
    async fn submit_session(&self, request: Request<LoginEvent>) -> Result<Response<Ack>, Status> {
        // Verify request is from controller
        self.validate_controller_ip(request.remote_addr())?;

        let event = request.into_inner();
        let dst_port = event.dst_port as u16;

        debug!(
            "Session request (activate={}): {} → {}:{}",
            event.activate, event.src_ip, event.dst_ip, dst_port
        );

        // Add or remove session rule
        let success = if event.activate {
            let add_rule = self.add_rule.lock().await;
            match add_rule(event.dst_ip, event.src_ip, dst_port) {
                Ok(_) => {
                    debug!(
                        "Session authorized: {} → {}:{}",
                        event.src_ip, event.dst_ip, dst_port
                    );
                    true
                }
                Err(e) => {
                    error!("Failed to add session: {}", e);
                    false
                }
            }
        } else {
            // TODO: Implement session deactivation
            info!("Session deactivation not implemented yet");
            true
        };

        let reply = Ack { success };
        Ok(Response::new(reply))
    }

    type MonitorSessionsStream =
        tokio_stream::wrappers::ReceiverStream<Result<SessionList, Status>>;

    async fn monitor_sessions(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::MonitorSessionsStream>, Status> {
        // Verify request is from controller
        self.validate_controller_ip(request.remote_addr())?;

        debug!("Starting session monitoring stream");

        let (_tx, rx) = tokio::sync::mpsc::channel(4);

        // TODO: Stream active sessions from BPF map

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

/// Starts the gRPC server with mTLS authentication.
pub async fn start_grpc_server(
    addr: SocketAddr,
    controller_ip: Ipv4Addr,
    add_rule: AddRuleFn,
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> Result<()> {
    let service = SessionManagerService::new(controller_ip, add_rule);

    debug!("Loading TLS certificates...");
    let cert = fs::read_to_string(cert_path).context("Failed to read certificate")?;
    let key = fs::read_to_string(key_path).context("Failed to read private key")?;
    let server_identity = Identity::from_pem(cert, key);

    let ca_pem = fs::read_to_string(ca_path).context("Failed to read CA certificate")?;
    let client_ca_cert = Certificate::from_pem(ca_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    info!("gRPC server starting with mTLS on {}", addr);
    debug!("Only accepting requests from: {}", controller_ip);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(SessionManagerServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| anyhow!("gRPC server error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_validate_controller_ip_success() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let add_rule: AddRuleFn = Arc::new(Mutex::new(|_, _, _| Ok(())));
        let service = SessionManagerService::new(controller_ip, add_rule);

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        let result = service.validate_controller_ip(Some(remote_addr));

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_controller_ip_unauthorized() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let add_rule: AddRuleFn = Arc::new(Mutex::new(|_, _, _| Ok(())));
        let service = SessionManagerService::new(controller_ip, add_rule);

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1234);
        let result = service.validate_controller_ip(Some(remote_addr));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_validate_controller_ip_no_address() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let add_rule: AddRuleFn = Arc::new(Mutex::new(|_, _, _| Ok(())));
        let service = SessionManagerService::new(controller_ip, add_rule);

        let result = service.validate_controller_ip(None);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_validate_controller_ip_ipv6_rejected() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let add_rule: AddRuleFn = Arc::new(Mutex::new(|_, _, _| Ok(())));
        let service = SessionManagerService::new(controller_ip, add_rule);

        let remote_addr = SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 1234);
        let result = service.validate_controller_ip(Some(remote_addr));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_session_manager_service_creation() {
        let controller_ip = Ipv4Addr::new(192, 168, 1, 1);
        let add_rule: AddRuleFn = Arc::new(Mutex::new(|_, _, _| Ok(())));
        let service = SessionManagerService::new(controller_ip, add_rule);

        assert_eq!(service.controller_ip, controller_ip);
    }
}
