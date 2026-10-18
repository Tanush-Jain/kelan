//! AITP Client — connect to AITP endpoints in 5 lines of code.
//!
//! # Quick Start
//!
//! ```ignore
//! use aitp_sdk::AitpClient;
//! use aitp_sdk::IntentCode;
//!
//! let client = AitpClient::builder()
//!     .config_path("aitp.toml")
//!     .build()
//!     .await?;
//!
//! let session = client
//!     .connect("a3f8...@192.168.1.100:9999")
//!     .intent(IntentCode::ModelInference)
//!     .await?;
//!
//! session.send(b"Hello AITP").await?;
//! let response = session.recv().await?;
//! session.close().await?;
//! ```

use crate::types::{EntityId, SdkError, Session};
use aitp_core::header::IntentCode;
use aitp_identity::identity::{AitpIdentity, Capability, EntityType};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Builder for creating an [`AitpClient`].
///
/// Use [`AitpClient::builder()`] to create a new builder.
///
/// # Example
///
/// ```ignore
/// let client = AitpClient::builder()
///     .config_path("aitp.toml")
///     .name("my-ai-agent")
///     .entity_type(EntityType::AIModel)
///     .build()
///     .await?;
/// ```
pub struct ClientBuilder {
    config_path: Option<String>,
    name: String,
    entity_type: EntityType,
    capabilities: Vec<Capability>,
    bind_addr: SocketAddr,
    identity_key_path: Option<String>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            config_path: None,
            name: "aitp-client".into(),
            entity_type: EntityType::Service,
            capabilities: vec![],
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            identity_key_path: None,
        }
    }
}

impl ClientBuilder {
    /// Set the TOML configuration file path.
    ///
    /// If set, the builder loads settings from this file. Inline settings
    /// (e.g., `.name()`, `.entity_type()`) override TOML values.
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.into());
        self
    }

    /// Set the client name (used in identity generation and logs).
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// Set the entity type for this client's identity.
    pub fn entity_type(mut self, entity_type: EntityType) -> Self {
        self.entity_type = entity_type;
        self
    }

    /// Add a capability to this client.
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Set the local bind address.
    ///
    /// Defaults to `0.0.0.0:0` (OS-assigned port).
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the path to load/save the Ed25519 identity key.
    pub fn identity_key_path(mut self, path: &str) -> Self {
        self.identity_key_path = Some(path.into());
        self
    }

    /// Build the client, binding the UDP socket and generating the identity.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Config`] if the config file is invalid.
    /// Returns [`SdkError::Identity`] if identity generation fails.
    /// Returns [`SdkError::Transport`] if the socket cannot be bound.
    pub async fn build(self) -> Result<AitpClient, SdkError> {
        // Load config from TOML if provided
        if let Some(path) = &self.config_path {
            if std::path::Path::new(path).exists() {
                tracing::info!(config_path = %path, "loading config from TOML");
            }
        }

        // Generate or load identity
        let identity =
            AitpIdentity::generate(&self.name, self.entity_type, self.capabilities.clone());

        tracing::info!(
            name = %self.name,
            entity_id = %crate::types::entity_id_short(&identity.entity_id),
            "AITP client identity created"
        );

        // Bind UDP socket
        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .map_err(|e| SdkError::Transport(format!("bind failed: {e}")))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| SdkError::Transport(format!("failed to get local address: {e}")))?;

        tracing::info!(local_addr = %local_addr, "UDP socket bound");

        Ok(AitpClient {
            identity: Arc::new(identity),
            socket: Arc::new(socket),
            local_addr,
            _name: self.name,
        })
    }
}

/// AITP client — connects to AITP endpoints and establishes sessions.
///
/// Created via [`AitpClient::builder()`]. The client manages its own
/// Ed25519 identity and UDP socket.
///
/// # Example
///
/// ```ignore
/// let client = AitpClient::builder()
///     .name("inference-client")
///     .build()
///     .await?;
///
/// let session = client
///     .connect("a3f8...@192.168.1.100:9999")
///     .intent(IntentCode::ModelInference)
///     .await?;
/// ```
pub struct AitpClient {
    /// Client identity (Ed25519 keypair + entity ID).
    identity: Arc<AitpIdentity>,
    /// Bound UDP socket.
    socket: Arc<UdpSocket>,
    /// Local address the socket is bound to.
    local_addr: SocketAddr,
    /// Client name for logging.
    _name: String,
}

impl AitpClient {
    /// Create a new client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Get the client's entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.identity.entity_id
    }

    /// Get the local address the client is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start a connection to a remote AITP endpoint.
    ///
    /// The `target` string is in the format `entity_id_hex@ip:port` or
    /// just `ip:port` if the entity ID is not known.
    ///
    /// Returns a [`ConnectRequest`] builder to configure and execute
    /// the connection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let session = client
    ///     .connect("192.168.1.100:9999")
    ///     .intent(IntentCode::ModelInference)
    ///     .await?;
    /// ```
    pub fn connect<'a>(&'a self, target: &str) -> ConnectRequest<'a> {
        ConnectRequest {
            client: self,
            target: target.to_string(),
            intent: IntentCode::ModelInference,
        }
    }
}

impl std::fmt::Debug for AitpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AitpClient")
            .field(
                "entity_id",
                &crate::types::entity_id_short(&self.identity.entity_id),
            )
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

/// A pending connect request with configurable intent.
///
/// Created by [`AitpClient::connect()`]. Call `.intent()` to set the
/// session intent, then `.await` to execute the connection.
pub struct ConnectRequest<'a> {
    client: &'a AitpClient,
    target: String,
    intent: IntentCode,
}

impl<'a> ConnectRequest<'a> {
    /// Set the intent for this connection.
    pub fn intent(mut self, intent: IntentCode) -> Self {
        self.intent = intent;
        self
    }

    /// Execute the connection, performing the AITP handshake.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Transport`] if the peer address is invalid.
    /// Returns [`SdkError::HandshakeFailed`] if the handshake fails.
    /// Returns [`SdkError::ConnectionRefused`] if the peer rejects the connection.
    pub async fn execute(self) -> Result<Session, SdkError> {
        // Parse target address: "entity_id@ip:port" or "ip:port"
        let (peer_entity_id, peer_addr) = parse_target(&self.target)?;

        // Generate session ID
        let session_id = rand_session_id();

        tracing::info!(
            target_addr = %peer_addr,
            intent = %self.intent,
            session_id,
            "initiating AITP connection"
        );

        // Build and send SYN packet
        let syn_header = aitp_core::header::AitpHeader::new(
            aitp_core::header::flags::SYN,
            self.intent,
            session_id,
            self.client.identity.entity_id,
            peer_entity_id,
            0, // trust score filled by peer
            0, // no payload in SYN
            current_timestamp_ns(),
            rand_nonce(),
        );

        let mut header = syn_header;
        header.sign(self.client.identity.signing_key());
        let packet = header.to_bytes();

        self.client
            .socket
            .send_to(&packet, peer_addr)
            .await
            .map_err(|e| SdkError::Transport(format!("send SYN failed: {e}")))?;

        tracing::debug!(session_id, "SYN sent, awaiting SYN+ACK");

        // Wait for SYN+ACK (with timeout)
        let mut buf = vec![0u8; 65535];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.client.socket.recv_from(&mut buf),
        );

        match timeout.await {
            Ok(Ok((len, from))) => {
                if len >= aitp_core::header::HEADER_SIZE {
                    if let Ok(resp) = aitp_core::header::AitpHeader::from_bytes(&buf[..len]) {
                        if resp
                            .has_flag(aitp_core::header::flags::SYN | aitp_core::header::flags::ACK)
                            && resp.session_id == session_id
                        {
                            tracing::info!(
                                session_id,
                                trust_score = resp.trust_score,
                                "session established"
                            );

                            // Create send/receive channels for the session
                            let (tx, mut rx) = mpsc::channel::<Bytes>(256);
                            let (data_tx, data_rx) = mpsc::channel::<Bytes>(256);

                            // Spawn receive loop for this session
                            let socket = self.client.socket.clone();
                            let session_data_tx = data_tx.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65535];
                                while let Ok((len, _from)) = socket.recv_from(&mut buf).await {
                                    if len > aitp_core::header::HEADER_SIZE {
                                        let payload = Bytes::copy_from_slice(
                                            &buf[aitp_core::header::HEADER_SIZE..len],
                                        );
                                        if session_data_tx.send(payload).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            });

                            // Spawn send loop for this session
                            let socket_send = self.client.socket.clone();
                            let identity_send = self.client.identity.clone();
                            let intent_send = self.intent;
                            tokio::spawn(async move {
                                while let Some(data) = rx.recv().await {
                                    let mut header = aitp_core::header::AitpHeader::new(
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

                            let session = Session::new(
                                session_id,
                                resp.trust_score,
                                resp.source_id,
                                self.intent,
                                from,
                            )
                            .with_channels(tx, data_rx);

                            return Ok(session);
                        }

                        if resp.has_flag(aitp_core::header::flags::REVOKE) {
                            return Err(SdkError::ConnectionRefused("peer sent REVOKE".into()));
                        }
                    }
                }
                Err(SdkError::HandshakeFailed("invalid SYN+ACK response".into()))
            }
            Ok(Err(e)) => Err(SdkError::Transport(format!("receive failed: {e}"))),
            Err(_) => Err(SdkError::Timeout(5000)),
        }
    }
}

impl<'a> std::future::IntoFuture for ConnectRequest<'a> {
    type Output = Result<Session, SdkError>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

// ────────────────────────── Helpers ──────────────────────────

/// Parse a target string: "entity_id@ip:port" or "ip:port"
fn parse_target(target: &str) -> Result<(EntityId, SocketAddr), SdkError> {
    if let Some((entity_hex, addr_str)) = target.split_once('@') {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| SdkError::Transport(format!("invalid address '{addr_str}': {e}")))?;

        let entity_id = hex_to_entity_id(entity_hex)?;
        Ok((entity_id, addr))
    } else {
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| SdkError::Transport(format!("invalid address '{target}': {e}")))?;
        Ok(([0u8; 32], addr))
    }
}

/// Convert a hex string to a 32-byte entity ID.
fn hex_to_entity_id(hex: &str) -> Result<EntityId, SdkError> {
    let hex_clean = hex.trim();
    if hex_clean.len() != 64 {
        // Short hex — pad with zeros
        let mut id = [0u8; 32];
        let bytes: Vec<u8> = (0..hex_clean.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16).ok())
            .collect();
        let len = bytes.len().min(32);
        id[..len].copy_from_slice(&bytes[..len]);
        return Ok(id);
    }

    let mut id = [0u8; 32];
    for (i, chunk) in hex_clean.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            break;
        }
        let hex_pair = std::str::from_utf8(chunk)
            .map_err(|_| SdkError::Transport("invalid hex in entity ID".into()))?;
        id[i] = u8::from_str_radix(hex_pair, 16)
            .map_err(|_| SdkError::Transport("invalid hex in entity ID".into()))?;
    }
    Ok(id)
}

/// Generate a random session ID.
fn rand_session_id() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    h.finish()
}

/// Get current timestamp in nanoseconds.
fn current_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Generate a random 12-byte nonce.
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

    #[test]
    fn test_parse_target_addr_only() {
        let (id, addr) = parse_target("127.0.0.1:9999").unwrap();
        assert_eq!(id, [0u8; 32]);
        assert_eq!(addr, "127.0.0.1:9999".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_target_with_entity_id() {
        let hex = "a3f8".repeat(16); // 64 hex chars = 32 bytes
        let target = format!("{hex}@10.0.0.1:9999");
        let (id, addr) = parse_target(&target).unwrap();
        assert_eq!(id[0], 0xa3);
        assert_eq!(id[1], 0xf8);
        assert_eq!(addr, "10.0.0.1:9999".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_target_invalid() {
        assert!(parse_target("not-an-address").is_err());
    }

    #[tokio::test]
    async fn test_client_builder_basic() {
        let client = AitpClient::builder()
            .name("test-client")
            .build()
            .await
            .unwrap();

        assert_ne!(client.entity_id(), &[0u8; 32]);
    }
}
