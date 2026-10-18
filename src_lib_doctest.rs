use std::sync::Arc;
use aitp_core::server::state::ServerState;
use aitp_core::events::EventBus;
use aitp_core::server::alert_engine::AlertEngine;

#[tokio::main]
async fn main() {
    let state = Arc::new(ServerState::new());
    let event_bus = EventBus::new();
    let alert_engine = AlertEngine::new(state.clone(), event_bus.subscribe());
    tokio::spawn(async move { alert_engine.run().await });
}
