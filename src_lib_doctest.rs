use aitp_core::events::EventBus;
use aitp_core::server::alert_engine::AlertEngine;
use aitp_core::server::state::ServerState;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let state = Arc::new(ServerState::new());
    let event_bus = EventBus::new();
    let alert_engine = AlertEngine::new(state.clone(), event_bus.subscribe());
    tokio::spawn(async move { alert_engine.run().await });
}
