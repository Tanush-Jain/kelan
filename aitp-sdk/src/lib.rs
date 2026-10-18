//! # AITP SDK — Connect AI systems in 10 lines of code
//!
//! The AITP SDK provides high-level, ergonomic APIs for building
//! applications that communicate over the Adaptive Intent Transport
//! Protocol (AITP).
//!
//! ## Quick Start — Server
//!
//! ```ignore
//! use aitp_sdk::AitpServer;
//!
//! let server = AitpServer::builder()
//!     .listen_addr("0.0.0.0:9999".parse().unwrap())
//!     .on_connection(|conn| async move {
//!         println!("New connection: {:?}", conn.intent);
//!         conn.accept().await
//!     })
//!     .on_payload(|session, data| async move {
//!         println!("Received {} bytes", data.len());
//!         session.send(b"ACK").await
//!     })
//!     .build()
//!     .await?;
//!
//! server.run().await;
//! ```
//!
//! ## Quick Start — Client
//!
//! ```ignore
//! use aitp_sdk::{AitpClient, IntentCode};
//!
//! let client = AitpClient::builder()
//!     .name("my-agent")
//!     .build()
//!     .await?;
//!
//! let session = client
//!     .connect("192.168.1.100:9999")
//!     .intent(IntentCode::ModelInference)
//!     .await?;
//!
//! session.send(b"Hello AITP").await?;
//! let response = session.recv().await?;
//! session.close().await?;
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Application Code               │
//! ├─────────────────────────────────────────────┤
//! │  AitpClient::builder()  AitpServer::builder()│
//! │       .connect()              .run()         │
//! ├─────────────────────────────────────────────┤
//! │     Connection / Session / SdkError          │
//! ├─────────────────────────────────────────────┤
//! │          aitp-core (transport layer)         │
//! │     AitpHeader · Ed25519 · UDP · Trust       │
//! └─────────────────────────────────────────────┘
//! ```

pub mod client;
pub mod server;
pub mod types;

// ────────────────────────── Re-exports ──────────────────────────

/// Re-export the client builder and type.
pub use client::AitpClient;

/// Re-export the server builder and type.
pub use server::AitpServer;

/// Re-export SDK types for convenience.
pub use types::{Connection, EntityId, RejectReason, SdkError, Session};

/// Re-export intent codes from aitp-core.
pub use aitp_core::header::IntentCode;

/// Re-export identity types.
pub use aitp_identity::identity::{Capability, EntityType};
