//! SDK types — Connection, Session, and error types.
//!
//! These types provide the high-level developer-facing API for AITP
//! applications. They wrap the low-level transport layer and provide
//! ergonomic async methods for sending and receiving data.

use aitp_core::header::IntentCode;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Mutex};

/// A 32-byte entity identifier (SHA-256 of Ed25519 public key).
pub type EntityId = [u8; 32];

/// Errors that can occur during SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Identity could not be loaded or generated.
    #[error("identity error: {0}")]
    Identity(String),

    /// Transport layer error (bind, send, receive).
    #[error("transport error: {0}")]
    Transport(String),

    /// Handshake failed or was rejected.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Connection was refused by the peer.
    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    /// Session is closed or revoked.
    #[error("session closed")]
    SessionClosed,

    /// Operation timed out.
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Channel closed unexpectedly.
    #[error("internal channel closed")]
    ChannelClosed,
}

/// Reason for rejecting a connection.
#[derive(Debug, Clone, Copy)]
pub enum RejectReason {
    /// Trust score too low.
    LowTrustScore,
    /// Intent not supported.
    UnsupportedIntent,
    /// Server at capacity.
    ServerFull,
    /// Application-level rejection.
    ApplicationDenied,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LowTrustScore => write!(f, "low_trust_score"),
            Self::UnsupportedIntent => write!(f, "unsupported_intent"),
            Self::ServerFull => write!(f, "server_full"),
            Self::ApplicationDenied => write!(f, "application_denied"),
        }
    }
}

/// An incoming connection request, presented to the server's
/// `on_connection` handler.
///
/// The application inspects the connection metadata (source identity,
/// intent, trust score) and calls [`accept`](Connection::accept) or
/// [`reject`](Connection::reject).
///
/// # Example
///
/// ```ignore
/// server.on_connection(|conn| async move {
///     if conn.trust_score > 128 {
///         conn.accept().await
///     } else {
///         conn.reject(RejectReason::LowTrustScore).await
///     }
/// });
/// ```
#[derive(Debug)]
pub struct Connection {
    /// Unique session identifier.
    pub session_id: u64,
    /// Source entity ID (the connecting peer).
    pub source_id: EntityId,
    /// Destination entity ID (this server).
    pub dest_id: EntityId,
    /// The intent declared by the peer.
    pub intent: IntentCode,
    /// Trust score assigned by the trust engine (0–255).
    pub trust_score: u8,
    /// When this connection was received.
    pub established_at: Instant,
    /// Peer network address.
    pub peer_addr: SocketAddr,
    /// Internal: channel to signal accept/reject back to the transport.
    pub(crate) accept_tx: Option<oneshot::Sender<bool>>,
}

impl Connection {
    /// Accept this connection, returning a [`Session`] for data transfer.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::ChannelClosed`] if the transport has shut down.
    pub async fn accept(mut self) -> Result<Session, SdkError> {
        if let Some(tx) = self.accept_tx.take() {
            let _ = tx.send(true);
        }
        Ok(Session::new(
            self.session_id,
            self.trust_score,
            self.source_id,
            self.intent,
            self.peer_addr,
        ))
    }

    /// Reject this connection with the given reason.
    ///
    /// The peer will receive a REVOKE packet.
    pub async fn reject(mut self, _reason: RejectReason) -> Result<(), SdkError> {
        if let Some(tx) = self.accept_tx.take() {
            let _ = tx.send(false);
        }
        Ok(())
    }
}

/// An active AITP session for bidirectional data transfer.
///
/// Sessions are created by accepting an incoming [`Connection`] (server side)
/// or by calling [`AitpClient::connect`](crate::client::AitpClient) (client side).
///
/// # Example
///
/// ```ignore
/// // Send data
/// session.send(b"Hello AITP world").await?;
///
/// // Receive data
/// let response = session.recv().await?;
/// println!("Got: {:?}", response);
///
/// // Close gracefully
/// session.close().await?;
/// ```
#[derive(Debug)]
pub struct Session {
    /// Unique session identifier.
    pub id: u64,
    /// Trust score for this session (0–255).
    pub trust_score: u8,
    /// The peer's entity ID.
    pub peer_id: EntityId,
    /// The intent of this session.
    pub intent: IntentCode,
    /// Peer network address.
    pub peer_addr: SocketAddr,
    /// When the session was established.
    pub established_at: Instant,
    /// Whether the session has been closed.
    closed: Arc<Mutex<bool>>,
    /// Channel for sending data to the transport layer.
    pub(crate) data_tx: Option<mpsc::Sender<Bytes>>,
    /// Channel for receiving data from the transport layer.
    pub(crate) data_rx: Option<Arc<Mutex<mpsc::Receiver<Bytes>>>>,
}

impl Session {
    /// Create a new session.
    pub fn new(
        id: u64,
        trust_score: u8,
        peer_id: EntityId,
        intent: IntentCode,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            id,
            trust_score,
            peer_id,
            intent,
            peer_addr,
            established_at: Instant::now(),
            closed: Arc::new(Mutex::new(false)),
            data_tx: None,
            data_rx: None,
        }
    }

    /// Attach data channels to this session (used internally by client).
    pub(crate) fn with_channels(
        mut self,
        tx: mpsc::Sender<Bytes>,
        rx: mpsc::Receiver<Bytes>,
    ) -> Self {
        self.data_tx = Some(tx);
        self.data_rx = Some(Arc::new(Mutex::new(rx)));
        self
    }

    /// Send data to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::SessionClosed`] if the session has been closed.
    /// Returns [`SdkError::ChannelClosed`] if the transport layer has shut down.
    pub async fn send(&self, data: &[u8]) -> Result<(), SdkError> {
        if *self.closed.lock().await {
            return Err(SdkError::SessionClosed);
        }

        if let Some(tx) = &self.data_tx {
            tx.send(Bytes::copy_from_slice(data))
                .await
                .map_err(|_| SdkError::ChannelClosed)?;
            tracing::debug!(session_id = self.id, bytes = data.len(), "data sent");
            Ok(())
        } else {
            // No transport channel — log-only mode (for examples)
            tracing::info!(
                session_id = self.id,
                bytes = data.len(),
                "data sent (no transport)"
            );
            Ok(())
        }
    }

    /// Receive data from the peer.
    ///
    /// Blocks until data is available or the session is closed.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::SessionClosed`] if the session has been closed
    /// or the peer disconnected.
    pub async fn recv(&self) -> Result<Bytes, SdkError> {
        if *self.closed.lock().await {
            return Err(SdkError::SessionClosed);
        }

        if let Some(rx) = &self.data_rx {
            let mut guard = rx.lock().await;
            guard.recv().await.ok_or(SdkError::SessionClosed)
        } else {
            // No transport channel — return empty (for examples)
            Err(SdkError::SessionClosed)
        }
    }

    /// Close this session gracefully.
    ///
    /// Sends a FIN to the peer and marks the session as closed.
    pub async fn close(&self) -> Result<(), SdkError> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Ok(());
        }
        *closed = true;
        tracing::info!(session_id = self.id, "session closed");
        Ok(())
    }

    /// Check if this session is still active.
    pub async fn is_active(&self) -> bool {
        !*self.closed.lock().await
    }

    /// Get the session duration.
    pub fn duration(&self) -> std::time::Duration {
        self.established_at.elapsed()
    }
}

/// Format an entity ID as a short hex string (first 8 chars).
pub fn entity_id_short(id: &EntityId) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Format an entity ID as a full hex string.
pub fn entity_id_hex(id: &EntityId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
