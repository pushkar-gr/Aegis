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
    Ack, Empty, IpChangeList, LoginEvent, SessionList,
    session_manager_server::{SessionManager, SessionManagerServer},
};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::{Mutex, broadcast};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};
use tracing::{debug, error, info, warn};

use crate::config::Config;

/// Callback function type for adding/removing firewall rules
type ModifyRulesFn = Arc<Mutex<dyn Fn(bool, u32, u32, u16) -> Result<()> + Send + Sync>>;

/// Callback function type for updating destination IPs
type UpdateIpFn = Arc<Mutex<dyn Fn(u32, u32) -> Result<usize> + Send + Sync>>;

#[derive(Clone)]
pub struct AuthInterceptor {
    pub controller_ip: Ipv4Addr,
}

impl tonic::service::Interceptor for AuthInterceptor {
    /// Verifies the request originates from the authorized controller.
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let remote_addr = request.remote_addr();

        match remote_addr {
            Some(addr) => {
                let ip = match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => ipv4,
                    std::net::IpAddr::V6(_) => {
                        warn!("Rejected request from IPv6 address: {}", addr.ip());
                        return Err(Status::permission_denied(
                            "Only IPv4 addresses are supported",
                        ));
                    }
                };

                if ip == self.controller_ip {
                    Ok(request)
                } else {
                    warn!(
                        "Rejected unauthorized IP: {} (expected {})",
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

/// SessionManager service implementation
pub struct SessionManagerService {
    modify_rules: ModifyRulesFn,
    update_ip: UpdateIpFn,
    monitor_tx: broadcast::Sender<Result<SessionList, Status>>,
}

impl SessionManagerService {
    pub fn new(
        modify_rules: ModifyRulesFn,
        update_ip: UpdateIpFn,
        monitor_tx: broadcast::Sender<Result<SessionList, Status>>,
    ) -> Self {
        Self {
            modify_rules,
            update_ip,
            monitor_tx,
        }
    }
}

#[tonic::async_trait]
impl SessionManager for SessionManagerService {
    async fn submit_session(&self, request: Request<LoginEvent>) -> Result<Response<Ack>, Status> {
        let event = request.into_inner();

        // Validate port range to prevent overflow
        if event.dst_port > u16::MAX as u32 {
            warn!("Invalid destination port: {}", event.dst_port);
            return Err(Status::invalid_argument("Destination port out of range"));
        }

        let dst_port = event.dst_port as u16;

        debug!(
            "Session request (activate={}): {} → {}:{}",
            event.activate, event.src_ip, event.dst_ip, dst_port
        );

        // Add or remove session rule
        let add_rule = self.modify_rules.lock().await;
        let success = match add_rule(event.activate, event.dst_ip, event.src_ip, dst_port) {
            Ok(_) => {
                debug!(
                    "Session modified (is_active: {}): {} → {}:{}",
                    event.activate, event.src_ip, event.dst_ip, dst_port
                );
                true
            }
            Err(e) => {
                error!("Failed to modify session: {}", e);
                false
            }
        };

        let reply = Ack { success };
        Ok(Response::new(reply))
    }

    type MonitorSessionsStream =
        tokio_stream::wrappers::ReceiverStream<Result<SessionList, Status>>;

    async fn monitor_sessions(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<Self::MonitorSessionsStream>, Status> {
        debug!("Starting session monitoring stream");

        let mut broadcast_rx = self.monitor_tx.subscribe();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("Monitor stream lagged, skipped {} messages", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn ip_change(&self, request: Request<IpChangeList>) -> Result<Response<Ack>, Status> {
        let ip_changes = request.into_inner();

        debug!("Received {} IP change events", ip_changes.ip_changes.len());

        let mut total_updated = 0;
        let mut has_errors = false;

        // Process each IP change event
        for change in ip_changes.ip_changes {
            debug!(
                "Processing IP change: {} → {}",
                change.old_ip, change.new_ip
            );

            // Update all sessions using the old IP to use the new IP
            match self.update_ip.lock().await(change.old_ip, change.new_ip) {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            "Updated {} sessions: old IP {} → new IP {}",
                            count, change.old_ip, change.new_ip
                        );
                        total_updated += count;
                    } else {
                        debug!("No sessions found for old IP {}", change.old_ip);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to update IP {} → {}: {}",
                        change.old_ip, change.new_ip, e
                    );
                    has_errors = true;
                }
            }
        }

        if total_updated > 0 {
            info!("Total sessions updated: {}", total_updated);
        }

        let reply = Ack {
            success: !has_errors,
        };
        Ok(Response::new(reply))
    }
}

/// Starts the gRPC server with mTLS authentication.
pub async fn start_grpc_server<'a>(
    config: &Config<'a>,
    addr: SocketAddr,
    modify_rules: ModifyRulesFn,
    update_ip: UpdateIpFn,
    monitor_tx: broadcast::Sender<Result<SessionList, Status>>,
) -> Result<()> {
    let service = SessionManagerService::new(modify_rules, update_ip, monitor_tx);

    let interceptor = AuthInterceptor {
        controller_ip: config.controller_ip,
    };

    debug!("Loading TLS certificates...");
    let cert = fs::read_to_string(&config.cert_file).context("Failed to read certificate")?;
    let key = fs::read_to_string(&config.key_file).context("Failed to read private key")?;
    let server_identity = Identity::from_pem(cert, key);

    let ca_pem = fs::read_to_string(&config.ca_file).context("Failed to read CA certificate")?;
    let client_ca_cert = Certificate::from_pem(ca_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    info!("gRPC server starting with mTLS on {}", addr);
    debug!("Only accepting requests from: {}", config.controller_ip);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(SessionManagerServer::with_interceptor(service, interceptor))
        .serve(addr)
        .await
        .map_err(|e| anyhow!("gRPC server error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tonic::service::Interceptor;

    #[test]
    fn test_interceptor_rejects_unauthorized_ip() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut interceptor = AuthInterceptor { controller_ip };

        let mut request = Request::new(());
        let unauthorized_ip = Ipv4Addr::new(10, 0, 0, 99);
        let remote_addr = SocketAddr::new(IpAddr::V4(unauthorized_ip), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = interceptor.call(request);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_interceptor_rejects_ipv6() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut interceptor = AuthInterceptor { controller_ip };

        let mut request = Request::new(());
        let remote_addr = SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = interceptor.call(request);

        assert!(result.is_err());
    }

    #[test]
    fn test_interceptor_rejects_no_address() {
        let controller_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut interceptor = AuthInterceptor { controller_ip };

        let request = Request::new(());

        let result = interceptor.call(request);

        assert!(result.is_err());
    }

    #[test]
    fn test_service_creation() {
        let modify_rules: ModifyRulesFn = Arc::new(Mutex::new(|_, _, _, _| Ok(())));
        let update_ip: UpdateIpFn = Arc::new(Mutex::new(|_, _| Ok(0)));
        let (tx, _) = broadcast::channel(4);

        let _service = SessionManagerService::new(modify_rules, update_ip, tx);
    }

    #[tokio::test]
    async fn test_ip_change_success() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let modify_rules: ModifyRulesFn = Arc::new(Mutex::new(|_, _, _, _| Ok(())));

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let update_ip: UpdateIpFn = Arc::new(Mutex::new(move |old_ip: u32, new_ip: u32| {
            assert_eq!(old_ip, 0x0A000001); // 10.0.0.1
            assert_eq!(new_ip, 0x0A000002); // 10.0.0.2
            called_clone.store(true, Ordering::SeqCst);
            Ok(3)
        }));

        let (tx, _) = broadcast::channel(4);
        let service = SessionManagerService::new(modify_rules, update_ip, tx);

        // Create a fake request
        let mut request = Request::new(IpChangeList {
            ip_changes: vec![session::IpChangeEvent {
                old_ip: 0x0A000001,
                new_ip: 0x0A000002,
            }],
        });

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = service.ip_change(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.into_inner().success);
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_ip_change_multiple_events() {
        let modify_rules: ModifyRulesFn = Arc::new(Mutex::new(|_, _, _, _| Ok(())));

        let call_count = Arc::new(std::sync::Mutex::new(0));
        let call_count_clone = call_count.clone();

        let update_ip: UpdateIpFn = Arc::new(Mutex::new(move |_old_ip: u32, _new_ip: u32| {
            *call_count_clone.lock().unwrap() += 1;
            Ok(1)
        }));

        let (tx, _) = broadcast::channel(4);
        let service = SessionManagerService::new(modify_rules, update_ip, tx);

        let mut request = Request::new(IpChangeList {
            ip_changes: vec![
                session::IpChangeEvent {
                    old_ip: 0x0A000001,
                    new_ip: 0x0A000002,
                },
                session::IpChangeEvent {
                    old_ip: 0x0A000003,
                    new_ip: 0x0A000004,
                },
                session::IpChangeEvent {
                    old_ip: 0x0A000005,
                    new_ip: 0x0A000006,
                },
            ],
        });

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = service.ip_change(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.into_inner().success);
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_ip_change_with_errors() {
        let modify_rules: ModifyRulesFn = Arc::new(Mutex::new(|_, _, _, _| Ok(())));
        let update_ip: UpdateIpFn = Arc::new(Mutex::new(|_old_ip: u32, _new_ip: u32| {
            Err(anyhow!("BPF update failed"))
        }));

        let (tx, _) = broadcast::channel(4);
        let service = SessionManagerService::new(modify_rules, update_ip, tx);

        let mut request = Request::new(IpChangeList {
            ip_changes: vec![session::IpChangeEvent {
                old_ip: 0x0A000001,
                new_ip: 0x0A000002,
            }],
        });

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = service.ip_change(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.into_inner().success);
    }

    #[tokio::test]
    async fn test_ip_change_empty_list() {
        let modify_rules: ModifyRulesFn = Arc::new(Mutex::new(|_, _, _, _| Ok(())));
        let update_ip: UpdateIpFn = Arc::new(Mutex::new(|_, _| Ok(0)));

        let (tx, _) = broadcast::channel(4);
        let service = SessionManagerService::new(modify_rules, update_ip, tx);

        let mut request = Request::new(IpChangeList { ip_changes: vec![] });

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        request.extensions_mut().insert(remote_addr);

        let result = service.ip_change(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.into_inner().success);
    }
}
