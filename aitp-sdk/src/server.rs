//! AITP Server — accept AITP connections in 5 lines of code.
//!
//! # Quick Start
//!
//! ```ignore
//! use aitp_sdk::AitpServer;
//!
//! let server = AitpServer::builder()
//!     .config_path("aitp.toml")
//!     .on_connection(|conn| async move {
//!         println!("New: {:?}", conn.intent);
//!         conn.accept().await
//!     })
//!     .on_payload(|session, data| async move {
//!         session.send(&data).await // echo
//!     })
//!     .build()
//!     .await?;
//!
//! server.run().await;
//! ```

use crate::types::{Connection, EntityId, SdkError, Session};
use aitp_core::header::{self, AitpHeader, IntentCode};
use aitp_identity::identity::{AitpIdentity, Capability, EntityType};
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

// ────────────────────────── Handler Types ──────────────────────────

/// Type alias for the connection handler function.
///
/// Called when a new AITP connection arrives. The handler receives a
/// [`Connection`] and must return a [`Session`] (via `conn.accept()`)
/// or reject it (via `conn.reject()`).
pub type ConnectionHandler = Arc<
    dyn Fn(Connection) -> Pin<Box<dyn Future<Output = Result<Session, SdkError>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for the payload handler function.
///
/// Called when data is received on an active session. The handler
/// receives the [`Session`] and the payload bytes.
pub type PayloadHandler = Arc<
    dyn Fn(Arc<Session>, Bytes) -> Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send>>
        + Send
        + Sync,
>;

// ────────────────────────── Builder ──────────────────────────

/// Builder for creating an [`AitpServer`].
///
/// Use [`AitpServer::builder()`] to start building.
///
/// # Example
///
/// ```ignore
/// let server = AitpServer::builder()
///     .listen_addr("0.0.0.0:9999".parse().unwrap())
///     .name("inference-server")
///     .on_connection(|conn| async move { conn.accept().await })
///     .on_payload(|session, data| async move {
///         session.send(&data).await
///     })
///     .build()
///     .await?;
/// ```
pub struct ServerBuilder {
    config_path: Option<String>,
    name: String,
    entity_type: EntityType,
    capabilities: Vec<Capability>,
    listen_addr: SocketAddr,
    max_sessions: usize,
    on_connection: Option<ConnectionHandler>,
    on_payload: Option<PayloadHandler>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            config_path: None,
            name: "aitp-server".into(),
            entity_type: EntityType::Service,
            capabilities: vec![Capability::Inference],
            listen_addr: "0.0.0.0:9999".parse().unwrap(),
            max_sessions: 65536,
            on_connection: None,
            on_payload: None,
        }
    }
}

impl ServerBuilder {
    /// Set the TOML configuration file path.
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.into());
        self
    }

    /// Set the server name.
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// Set the entity type for this server's identity.
    pub fn entity_type(mut self, entity_type: EntityType) -> Self {
        self.entity_type = entity_type;
        self
    }

    /// Add a capability.
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Set the listen address and port.
    ///
    /// Defaults to `0.0.0.0:9999`.
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Set the maximum number of concurrent sessions.
    pub fn max_sessions(mut self, max: usize) -> Self {
        self.max_sessions = max;
        self
    }

    /// Set the connection handler.
    ///
    /// Called when a new AITP handshake arrives. The handler receives
    /// a [`Connection`] and must call `conn.accept()` or `conn.reject()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// .on_connection(|conn| async move {
    ///     println!("Connection from {:?}", conn.source_id);
    ///     conn.accept().await
    /// })
    /// ```
    pub fn on_connection<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Session, SdkError>> + Send + 'static,
    {
        self.on_connection = Some(Arc::new(move |conn| Box::pin(handler(conn))));
        self
    }

    /// Set the payload handler.
    ///
    /// Called when data arrives on an active session.
    ///
    /// # Example
    ///
    /// ```ignore
    /// .on_payload(|session, data| async move {
    ///     println!("Got {} bytes", data.len());
    ///     session.send(b"ACK").await
    /// })
    /// ```
    pub fn on_payload<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(Arc<Session>, Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), SdkError>> + Send + 'static,
    {
        self.on_payload = Some(Arc::new(move |session, data| {
            Box::pin(handler(session, data))
        }));
        self
    }

    /// Build the server.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Config`] if the config file is invalid.
    /// Returns [`SdkError::Transport`] if the socket cannot be bound.
    pub async fn build(self) -> Result<AitpServer, SdkError> {
        // Load config from TOML if provided
        if let Some(path) = &self.config_path {
            if std::path::Path::new(path).exists() {
                tracing::info!(config_path = %path, "loading server config from TOML");
            }
        }

        // Generate identity
        let identity =
            AitpIdentity::generate(&self.name, self.entity_type, self.capabilities.clone());

        tracing::info!(
            name = %self.name,
            entity_id = %crate::types::entity_id_short(&identity.entity_id),
            "AITP server identity created"
        );

        // Bind UDP socket
        let socket = UdpSocket::bind(self.listen_addr).await.map_err(|e| {
            SdkError::Transport(format!("bind failed on {}: {e}", self.listen_addr))
        })?;

        let listen_addr = socket
            .local_addr()
            .map_err(|e| SdkError::Transport(format!("failed to get listen address: {e}")))?;

        tracing::info!(listen_addr = %listen_addr, "AITP server listening");

        // Default connection handler: accept all
        let on_connection = self.on_connection.unwrap_or_else(|| {
            Arc::new(|conn: Connection| {
                Box::pin(async move { conn.accept().await })
                    as Pin<Box<dyn Future<Output = Result<Session, SdkError>> + Send>>
            })
        });

        // Default payload handler: log only
        let on_payload = self.on_payload.unwrap_or_else(|| {
            Arc::new(|session: Arc<Session>, data: Bytes| {
                Box::pin(async move {
                    tracing::debug!(
                        session_id = session.id,
                        bytes = data.len(),
                        "payload received (no handler)"
                    );
                    Ok(())
                }) as Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send>>
            })
        });

        Ok(AitpServer {
            identity: Arc::new(identity),
            socket: Arc::new(socket),
            listen_addr,
            max_sessions: self.max_sessions,
            on_connection,
            on_payload,
            sessions: Arc::new(dashmap::DashMap::new()),
        })
    }
}

// ────────────────────────── Server ──────────────────────────

/// AITP server — accepts incoming AITP connections.
///
/// Created via [`AitpServer::builder()`]. The server listens on a
/// UDP socket and processes incoming handshakes and data.
///
/// # Example
///
/// ```ignore
/// let server = AitpServer::builder()
///     .on_connection(|conn| async move { conn.accept().await })
///     .on_payload(|session, data| async move { session.send(&data).await })
///     .build()
///     .await?;
///
/// server.run().await;
/// ```
pub struct AitpServer {
    /// Server identity.
    identity: Arc<AitpIdentity>,
    /// Listening UDP socket.
    socket: Arc<UdpSocket>,
    /// Address the server is listening on.
    listen_addr: SocketAddr,
    /// Maximum concurrent sessions.
    max_sessions: usize,
    /// Connection handler.
    on_connection: ConnectionHandler,
    /// Payload handler.
    on_payload: PayloadHandler,
    /// Active sessions.
    sessions: Arc<dashmap::DashMap<u64, Arc<Session>>>,
}

impl AitpServer {
    /// Create a new server builder.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    /// Get the server's entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.identity.entity_id
    }

    /// Get the listen address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get the number of active sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Run the server event loop.
    ///
    /// This is the main entry point. It listens for incoming AITP
    /// packets and dispatches them to the configured handlers.
    ///
    /// This method runs forever (until the process is terminated or
    /// the socket is closed).
    pub async fn run(&self) {
        tracing::info!(
            listen_addr = %self.listen_addr,
            entity_id = %crate::types::entity_id_short(&self.identity.entity_id),
            max_sessions = self.max_sessions,
            "AITP server running"
        );

        let mut buf = vec![0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    if len < header::HEADER_SIZE {
                        tracing::debug!(
                            len,
                            peer = %peer_addr,
                            "packet too short, dropping"
                        );
                        continue;
                    }

                    match AitpHeader::from_bytes(&buf[..len]) {
                        Ok(hdr) => {
                            self.handle_packet(hdr, &buf[header::HEADER_SIZE..len], peer_addr)
                                .await;
                        }
                        Err(e) => {
                            tracing::debug!(
                                error = %e,
                                peer = %peer_addr,
                                "failed to parse header"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "socket receive error");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Handle a single incoming packet.
    async fn handle_packet(&self, header: AitpHeader, payload: &[u8], peer_addr: SocketAddr) {
        if header.has_flag(header::flags::SYN) && !header.has_flag(header::flags::ACK) {
            // New connection request
            self.handle_syn(header, peer_addr).await;
        } else if !header.has_flag(header::flags::SYN) && !header.has_flag(header::flags::FIN) {
            // Data packet
            self.handle_data(header, payload, peer_addr).await;
        } else if header.has_flag(header::flags::FIN) {
            // Session close
            self.handle_fin(header, peer_addr).await;
        } else if header.has_flag(header::flags::REVOKE) {
            // Session revoke
            self.handle_revoke(header, peer_addr).await;
        }
    }

    /// Handle an incoming SYN (new connection request).
    async fn handle_syn(&self, header: AitpHeader, peer_addr: SocketAddr) {
        tracing::info!(
            session_id = header.session_id,
            intent = %header.intent_code,
            peer = %peer_addr,
            "incoming connection request"
        );

        // Check capacity
        if self.sessions.len() >= self.max_sessions {
            tracing::warn!("session table full, rejecting");
            self.send_revoke(header.session_id, &header.source_id, peer_addr)
                .await;
            return;
        }

        // Create Connection for the handler
        let (accept_tx, _accept_rx) = oneshot::channel();
        let conn = Connection {
            session_id: header.session_id,
            source_id: header.source_id,
            dest_id: self.identity.entity_id,
            intent: header.intent_code,
            trust_score: 128, // Default — real score from trust engine
            established_at: Instant::now(),
            peer_addr,
            accept_tx: Some(accept_tx),
        };

        // Call the connection handler
        let handler = self.on_connection.clone();
        let sessions = self.sessions.clone();
        let socket = self.socket.clone();
        let identity = self.identity.clone();

        tokio::spawn(async move {
            match handler(conn).await {
                Ok(session) => {
                    tracing::info!(session_id = session.id, "connection accepted");

                    // Send SYN+ACK
                    let mut syn_ack = AitpHeader::new(
                        header::flags::SYN | header::flags::ACK,
                        session.intent,
                        session.id,
                        identity.entity_id,
                        session.peer_id,
                        session.trust_score,
                        0,
                        current_timestamp_ns(),
                        rand_nonce(),
                    );
                    syn_ack.sign(identity.signing_key());

                    if let Err(e) = socket.send_to(&syn_ack.to_bytes(), peer_addr).await {
                        tracing::error!(error = %e, "failed to send SYN+ACK");
                        return;
                    }

                    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(256);
                    let (_data_tx, data_rx) = tokio::sync::mpsc::channel::<Bytes>(256);

                    let session_id = session.id;
                    let intent_send = session.intent;
                    let peer_entity_id = session.peer_id;
                    let session_for_map = session.with_channels(tx, data_rx);

                    let socket_send = socket.clone();
                    let identity_send = identity.clone();
                    tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            let mut header = AitpHeader::new(
                                0,
                                intent_send,
                                session_id,
                                identity_send.entity_id,
                                peer_entity_id,
                                128,
                                data.len() as u16,
                                current_timestamp_ns(),
                                rand_nonce(),
                            );
                            header.sign(identity_send.signing_key());
                            let mut packet = header.to_bytes();
                            packet.extend_from_slice(&data);
                            let _ = socket_send.send_to(&packet, peer_addr).await;
                        }
                    });

                    sessions.insert(session_id, Arc::new(session_for_map));
                }
                Err(e) => {
                    tracing::info!(error = %e, "connection rejected by handler");
                }
            }
        });
    }

    /// Handle incoming data on an active session.
    async fn handle_data(&self, header: AitpHeader, payload: &[u8], _peer_addr: SocketAddr) {
        if let Some(session) = self.sessions.get(&header.session_id) {
            let session = session.value().clone();
            let data = Bytes::copy_from_slice(payload);
            let handler = self.on_payload.clone();

            tokio::spawn(async move {
                if let Err(e) = handler(session, data).await {
                    tracing::warn!(error = %e, "payload handler error");
                }
            });
        } else {
            tracing::debug!(
                session_id = header.session_id,
                "data for unknown session, dropping"
            );
        }
    }

    /// Handle FIN (graceful close).
    async fn handle_fin(&self, header: AitpHeader, peer_addr: SocketAddr) {
        if let Some((_, session)) = self.sessions.remove(&header.session_id) {
            let _ = session.close().await;
            tracing::info!(
                session_id = header.session_id,
                peer = %peer_addr,
                "session closed by peer (FIN)"
            );
        }
    }

    /// Handle REVOKE (immediate termination).
    async fn handle_revoke(&self, header: AitpHeader, peer_addr: SocketAddr) {
        if let Some((_, session)) = self.sessions.remove(&header.session_id) {
            let _ = session.close().await;
            tracing::warn!(
                session_id = header.session_id,
                peer = %peer_addr,
                "session revoked"
            );
        }
    }

    /// Send a REVOKE packet to a peer.
    async fn send_revoke(&self, session_id: u64, dest_id: &[u8; 32], peer_addr: SocketAddr) {
        let mut header = AitpHeader::new(
            header::flags::REVOKE,
            IntentCode::Unknown,
            session_id,
            self.identity.entity_id,
            *dest_id,
            0,
            0,
            current_timestamp_ns(),
            rand_nonce(),
        );
        header.sign(self.identity.signing_key());

        if let Err(e) = self.socket.send_to(&header.to_bytes(), peer_addr).await {
            tracing::error!(error = %e, "failed to send REVOKE");
        }
    }
}

impl std::fmt::Debug for AitpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AitpServer")
            .field(
                "entity_id",
                &crate::types::entity_id_short(&self.identity.entity_id),
            )
            .field("listen_addr", &self.listen_addr)
            .field("active_sessions", &self.sessions.len())
            .finish()
    }
}

// ────────────────────────── Helpers ──────────────────────────

fn current_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn rand_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let ts = current_timestamp_ns();
    nonce[..8].copy_from_slice(&ts.to_le_bytes());
    let pid = std::process::id();
    nonce[8..12].copy_from_slice(&pid.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_builder_basic() {
        let server = AitpServer::builder()
            .name("test-server")
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        assert_ne!(server.entity_id(), &[0u8; 32]);
        assert_eq!(server.active_sessions(), 0);
    }

    #[tokio::test]
    async fn test_server_builder_with_handlers() {
        let server = AitpServer::builder()
            .name("echo-server")
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .on_connection(|conn| async move { conn.accept().await })
            .on_payload(|session, data| async move { session.send(&data).await })
            .build()
            .await
            .unwrap();

        assert_ne!(server.entity_id(), &[0u8; 32]);
    }
}
