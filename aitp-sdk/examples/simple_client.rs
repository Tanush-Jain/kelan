//! Simple Client — connects to an AITP server and sends data.
//!
//! # Run
//!
//! ```bash
//! # Start the echo server first:
//! cargo run --example simple_echo_server
//!
//! # Then in another terminal:
//! cargo run --example simple_client
//! ```

use aitp_sdk::{AitpClient, IntentCode};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let client = AitpClient::builder()
        .name("simple-client")
        .build()
        .await
        .expect("failed to create client");

    println!("🔌 AITP Client created");
    println!(
        "   Entity ID: {}",
        aitp_sdk::types::entity_id_hex(client.entity_id())
    );
    println!("   Local addr: {}", client.local_addr());

    let target = std::env::var("AITP_TARGET").unwrap_or_else(|_| "127.0.0.1:9999".to_string());
    println!("\n📡 Connecting to {}...", target);

    match client
        .connect(&target)
        .intent(IntentCode::ModelInference)
        .await
    {
        Ok(session) => {
            println!("✅ Session {} established!", session.id);
            println!("   Trust score: {}", session.trust_score);
            println!(
                "   Peer: {:?}",
                aitp_sdk::types::entity_id_short(&session.peer_id)
            );

            // Send a message
            let message = b"Hello AITP world! This is model inference data.";
            println!("\n📤 Sending {} bytes...", message.len());
            if let Err(e) = session.send(message).await {
                println!("❌ Send error: {}", e);
            }

            // Wait for response
            println!("📥 Waiting for response...");
            match tokio::time::timeout(std::time::Duration::from_secs(3), session.recv()).await {
                Ok(Ok(data)) => {
                    println!("✅ Got response: {} bytes", data.len());
                    if let Ok(text) = std::str::from_utf8(&data) {
                        println!("   Content: {}", text);
                    }
                }
                Ok(Err(e)) => println!("❌ Receive error: {}", e),
                Err(_) => println!("⏱  No response within 3 seconds"),
            }

            // Close
            session.close().await.ok();
            println!("\n👋 Session closed");
        }
        Err(e) => {
            println!("❌ Connection failed: {}", e);
            println!("   Make sure the echo server is running:");
            println!("   cargo run --example simple_echo_server");
        }
    }
}
