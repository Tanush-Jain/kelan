//! Simple Echo Server — accepts connections and echoes payloads.
//!
//! # Run
//!
//! ```bash
//! cargo run --example simple_echo_server
//! ```

use aitp_sdk::AitpServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let server = AitpServer::builder()
        .name("echo-server")
        .listen_addr("0.0.0.0:9999".parse().unwrap())
        .on_connection(|conn| async move {
            println!(
                "✅ New connection from {:?}, intent: {:?}, trust: {}",
                aitp_sdk::types::entity_id_short(&conn.source_id),
                conn.intent,
                conn.trust_score,
            );
            conn.accept().await
        })
        .on_payload(|session, data| async move {
            println!(
                "📦 Session {} received {} bytes — echoing back",
                session.id,
                data.len()
            );
            session.send(&data).await
        })
        .build()
        .await
        .expect("failed to start echo server");

    println!("🚀 AITP Echo Server listening on {}", server.listen_addr());
    println!(
        "   Entity ID: {}",
        aitp_sdk::types::entity_id_hex(server.entity_id())
    );
    println!("   Press Ctrl+C to stop");

    server.run().await;
}
