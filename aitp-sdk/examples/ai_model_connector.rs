//! AI Model Connector — simulates LLM-to-LLM communication.
//!
//! Demonstrates how two AI models would use AITP for inference
//! requests, with ModelInference intent and structured payloads.
//!
//! # Run
//!
//! ```bash
//! cargo run --example ai_model_connector
//! ```

use aitp_sdk::{AitpClient, AitpServer, IntentCode};
use std::sync::Arc;
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("🤖 AI Model Connector — LLM-to-LLM via AITP");
    println!("─────────────────────────────────────────────");

    let ready = Arc::new(Notify::new());
    let ready_clone = ready.clone();

    // Start the "inference server" (Model B)
    let server = AitpServer::builder()
        .name("model-b-llama")
        .listen_addr("127.0.0.1:0".parse().unwrap())
        .on_connection(|conn| async move {
            println!("\n🔗 Model B: incoming inference request");
            println!("   Intent: {:?}", conn.intent);
            println!(
                "   From: {}",
                aitp_sdk::types::entity_id_short(&conn.source_id)
            );
            conn.accept().await
        })
        .on_payload(|session, data| async move {
            let request = String::from_utf8_lossy(&data);
            println!("📨 Model B received: {}", request);

            // Simulate inference
            let response = format!(
                r#"{{"model":"llama-3","response":"The answer is 42","tokens":12,"session":{}}}"#,
                session.id
            );
            println!("📤 Model B responding: {}", response);
            session.send(response.as_bytes()).await
        })
        .build()
        .await
        .expect("failed to start Model B");

    let server_addr = server.listen_addr();
    println!("✅ Model B (Llama) listening on {}", server_addr);

    // Spawn server
    tokio::spawn(async move {
        ready_clone.notify_one();
        server.run().await;
    });

    ready.notified().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Create the "inference client" (Model A)
    let client = AitpClient::builder()
        .name("model-a-gpt")
        .build()
        .await
        .expect("failed to create Model A client");

    println!("✅ Model A (GPT) created");

    // Connect Model A → Model B
    let target = format!("127.0.0.1:{}", server_addr.port());
    println!("\n🔌 Model A connecting to Model B at {}...", target);

    match client
        .connect(&target)
        .intent(IntentCode::ModelInference)
        .await
    {
        Ok(session) => {
            println!("✅ AI-to-AI session established (ID: {})", session.id);

            // Send inference request
            let request = r#"{"prompt":"What is the meaning of life?","max_tokens":50}"#;
            println!("\n📤 Model A → Model B: {}", request);
            session.send(request.as_bytes()).await.ok();

            // Wait for response
            match tokio::time::timeout(std::time::Duration::from_secs(2), session.recv()).await {
                Ok(Ok(resp)) => {
                    let text = String::from_utf8_lossy(&resp);
                    println!("📥 Model B → Model A: {}", text);
                }
                _ => println!("⏱  No response within timeout"),
            }

            session.close().await.ok();
            println!("\n✅ AI-to-AI inference complete!");
        }
        Err(e) => println!("❌ Connection failed: {}", e),
    }
}
