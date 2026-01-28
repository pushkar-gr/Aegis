//! # gRPC Server for Aegis Agent
//!
//! This module implements the SessionManager gRPC service that allows
//! the controller to submit session events and monitor active sessions.

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

/// Type alias for the add rule callback
type AddRuleFn = Arc<Mutex<dyn Fn(u32, u32, u16) -> Result<()> + Send + Sync>>;

/// SessionManagerService implements the gRPC service
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

    /// Validates that the request comes from the controller
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
                        "Rejected request from unauthorized IP: {} (expected: {})",
                        ip, self.controller_ip
                    );
                    Err(Status::permission_denied(
                        "Only requests from controller are accepted",
                    ))
                }
            }
            None => {
                warn!("Rejected request with no remote address");
                Err(Status::permission_denied(
                    "Unable to determine remote address",
                ))
            }
        }
    }
}

#[tonic::async_trait]
impl SessionManager for SessionManagerService {
    async fn submit_session(&self, request: Request<LoginEvent>) -> Result<Response<Ack>, Status> {
        // Validate controller IP
        self.validate_controller_ip(request.remote_addr())?;

        let event = request.into_inner();

        let dst_port = event.dst_port as u16;

        debug!(
            "Incoming SubmitSession Request (activate: {}). {} -> {}:{}",
            event.activate, event.src_ip, event.dst_ip, dst_port
        );

        // Add or remove session rule in BPF map
        let success = if event.activate {
            let add_rule = self.add_rule.lock().await;
            match add_rule(event.dst_ip, event.src_ip, dst_port) {
                Ok(_) => {
                    debug!(
                        "Successfully added session rule: {} -> {}:{}",
                        event.src_ip, event.dst_ip, dst_port
                    );
                    true
                }
                Err(e) => {
                    error!("Failed to add session rule: {}", e);
                    false
                }
            }
        } else {
            // TODO: Implement rule removal when activate=false
            info!("Session deactivation not yet implemented");
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
        // Validate controller IP
        self.validate_controller_ip(request.remote_addr())?;

        debug!("Starting session monitoring stream");

        // Create a channel for streaming responses
        let (_tx, rx) = tokio::sync::mpsc::channel(4);

        // TODO: Implement session monitoring from BPF map

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

/// Starts the gRPC server on the specified address
pub async fn start_grpc_server(
    addr: SocketAddr,
    controller_ip: Ipv4Addr,
    add_rule: AddRuleFn,
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> Result<()> {
    let service = SessionManagerService::new(controller_ip, add_rule);

    debug!("Loading mTLS certificates...");
    let cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
    let key = fs::read_to_string(key_path).context("Failed to read key file")?;
    let server_identity = Identity::from_pem(cert, key);

    let ca_pem = fs::read_to_string(ca_path).context("Failed to read CA file")?;
    let client_ca_cert = Certificate::from_pem(ca_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    info!("Starting gRPC server with mTLS on {}", addr);
    debug!("Only accepting requests from controller: {}", controller_ip);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(SessionManagerServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| anyhow!("gRPC server error: {}", e))?;

    Ok(())
}
