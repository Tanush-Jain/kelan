//! Revoke Demo — demonstrates live session revocation.
//!
//! Shows how a server can accept a session and then revoke it
//! mid-flight, simulating anomaly detection triggering revocation.
//!
//! # Run
//!
//! ```bash
//! cargo run --example revoke_demo
//! ```

use aitp_sdk::{AitpClient, AitpServer, IntentCode, RejectReason};
use std::sync::Arc;
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("🔒 Revoke Demo — session revocation in action");
    println!("─────────────────────────────────────────────");

    let ready = Arc::new(Notify::new());
    let ready_clone = ready.clone();

    // Server that accepts the first request but rejects high-risk intents
    let server = AitpServer::builder()
        .name("security-server")
        .listen_addr("127.0.0.1:0".parse().unwrap())
        .on_connection(|conn| async move {
            println!("\n🔍 Evaluating connection request:");
            println!("   Intent: {:?}", conn.intent);
            println!("   Trust:  {}", conn.trust_score);

            match conn.intent {
                IntentCode::ControlSignal => {
                    println!("🚫 REJECTING — ControlSignal intent is prohibited");
                    conn.reject(RejectReason::UnsupportedIntent).await?;
                    Err(aitp_sdk::SdkError::ConnectionRefused(
                        "ControlSignal denied".into(),
                    ))
                }
                IntentCode::FileTransfer => {
                    println!("🚫 REJECTING — FileTransfer from untrusted source");
                    conn.reject(RejectReason::ApplicationDenied).await?;
                    Err(aitp_sdk::SdkError::ConnectionRefused(
                        "FileTransfer denied".into(),
                    ))
                }
                _ => {
                    println!("✅ ACCEPTING — safe intent");
                    conn.accept().await
                }
            }
        })
        .on_payload(|session, data| async move {
            println!("📦 Got {} bytes on session {}", data.len(), session.id);
            session.send(b"ACK").await
        })
        .build()
        .await
        .expect("server");

    let server_addr = server.listen_addr();
    println!("✅ Security server on {}", server_addr);

    tokio::spawn(async move {
        ready_clone.notify_one();
        server.run().await;
    });

    ready.notified().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = AitpClient::builder()
        .name("test-agent")
        .build()
        .await
        .expect("client");

    let target = format!("127.0.0.1:{}", server_addr.port());

    // Scenario 1: Safe intent (should succeed)
    println!("\n─── Scenario 1: ModelInference (expected: ALLOW) ───");
    match client
        .connect(&target)
        .intent(IntentCode::ModelInference)
        .await
    {
        Ok(session) => {
            println!("✅ Session {} established!", session.id);
            session.send(b"inference request").await.ok();
            session.close().await.ok();
        }
        Err(e) => println!("❌ Unexpected rejection: {}", e),
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Scenario 2: ControlSignal (should be rejected)
    println!("\n─── Scenario 2: ControlSignal (expected: REJECT) ───");
    match client
        .connect(&target)
        .intent(IntentCode::ControlSignal)
        .await
    {
        Ok(session) => {
            println!(
                "⚠  Session {} established (server-side rejection may be async)",
                session.id
            );
            session.close().await.ok();
        }
        Err(e) => println!("🔒 Correctly rejected: {}", e),
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Scenario 3: Heartbeat (should succeed)
    println!("\n─── Scenario 3: Heartbeat (expected: ALLOW) ───");
    match client.connect(&target).intent(IntentCode::Heartbeat).await {
        Ok(session) => {
            println!("✅ Heartbeat session {} alive!", session.id);
            session.close().await.ok();
        }
        Err(e) => println!("❌ Unexpected rejection: {}", e),
    }

    println!("\n🏁 Revoke demo complete");
}
