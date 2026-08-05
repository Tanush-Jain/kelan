//! Multi-Session — client managing 100 concurrent sessions.
//!
//! Demonstrates AITP's ability to handle many concurrent
//! AI-to-AI sessions simultaneously.
//!
//! # Run
//!
//! ```bash
//! cargo run --example multi_session
//! ```

use aitp_sdk::{AitpClient, AitpServer, IntentCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("warn").init();

    println!("⚡ Multi-Session Demo — 100 concurrent AITP sessions");
    println!("─────────────────────────────────────────────────────");

    let connections = Arc::new(AtomicU64::new(0));
    let payloads = Arc::new(AtomicU64::new(0));
    let conns_clone = connections.clone();
    let pays_clone = payloads.clone();

    let ready = Arc::new(Notify::new());
    let ready_clone = ready.clone();

    // Start server that counts connections and echoes
    let server = AitpServer::builder()
        .name("multi-session-server")
        .listen_addr("127.0.0.1:0".parse().unwrap())
        .max_sessions(200)
        .on_connection(move |conn| {
            let conns = conns_clone.clone();
            async move {
                conns.fetch_add(1, Ordering::Relaxed);
                conn.accept().await
            }
        })
        .on_payload(move |session, data| {
            let pays = pays_clone.clone();
            async move {
                pays.fetch_add(1, Ordering::Relaxed);
                session.send(&data).await
            }
        })
        .build()
        .await
        .expect("server start");

    let server_addr = server.listen_addr();
    println!("✅ Server listening on {}", server_addr);

    tokio::spawn(async move {
        ready_clone.notify_one();
        server.run().await;
    });

    ready.notified().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Spawn 100 concurrent client sessions
    let num_sessions = 100u32;
    let start = std::time::Instant::now();

    println!("🚀 Spawning {} concurrent sessions...", num_sessions);

    let mut handles = Vec::new();

    for i in 0..num_sessions {
        let target = format!("127.0.0.1:{}", server_addr.port());
        let handle = tokio::spawn(async move {
            let client = AitpClient::builder()
                .name(&format!("client-{i}"))
                .build()
                .await
                .expect("client");

            match client
                .connect(&target)
                .intent(IntentCode::ModelInference)
                .await
            {
                Ok(session) => {
                    let msg = format!("message from client {i}");
                    session.send(msg.as_bytes()).await.ok();
                    session.close().await.ok();
                    true
                }
                Err(_) => false,
            }
        });
        handles.push(handle);
    }

    // Wait for all
    let mut success = 0u32;
    let mut failed = 0u32;
    for handle in handles {
        match handle.await {
            Ok(true) => success += 1,
            Ok(false) => failed += 1,
            Err(_) => failed += 1,
        }
    }

    let elapsed = start.elapsed();

    println!("\n📊 Results:");
    println!("   Total sessions:     {}", num_sessions);
    println!("   Successful:         {}", success);
    println!("   Failed:             {}", failed);
    println!(
        "   Server connections: {}",
        connections.load(Ordering::Relaxed)
    );
    println!(
        "   Server payloads:    {}",
        payloads.load(Ordering::Relaxed)
    );
    println!("   Total time:         {:.2?}", elapsed);
    println!(
        "   Sessions/sec:       {:.0}",
        num_sessions as f64 / elapsed.as_secs_f64()
    );
}
