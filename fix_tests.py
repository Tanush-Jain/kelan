import re

with open('/Users/wopsy/programming/Project/kelan-core/aitp-server/tests/integration_tests.rs', 'r') as f:
    text = f.read()

# Replace block 1: SERVER_INIT and ensure_server_running -> spawn_test_server
text = re.sub(
    r"use tokio::sync::OnceCell;[\s\S]*?async fn ensure_server_running\(\) \{[\s\S]*?\}\)\.await;\n\}",
    """use std::net::TcpListener;
use tokio::task::JoinHandle;

async fn spawn_test_server() -> (u16, JoinHandle<()>) {
    std::env::set_var("KELAN_JWT_SECRET", "kelan-test-secret-for-ci");
    std::env::set_var("AITP_JWT_SECRET", "kelan-test-secret-for-ci");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        aitp_server::run_with_listener(listener).await.unwrap();
    });
    // Give the server a moment to be ready
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (port, handle)
}""", text)

# Replace block 2: kelan_base_url()
text = re.sub(
    r"fn kelan_base_url\(\) -> String \{[\s\S]*?\}",
    """fn kelan_base_url(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}""", text)

# Replace block 3: helpers taking port
text = re.sub(
    r"async fn http_get\(path: &str\) -> reqwest::Response \{[\s\S]*?get\(format!\(\"\{\}\{\}\", kelan_base_url\(\), path\)\)",
    """async fn http_get(port: u16, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{}{}", kelan_base_url(port), path))""", text)

text = re.sub(
    r"async fn http_post_json\(path: &str, body: serde_json::Value\) -> reqwest::Response \{[\s\S]*?post\(format!\(\"\{\}\{\}\", kelan_base_url\(\), path\)\)",
    """async fn http_post_json(port: u16, path: &str, body: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}{}", kelan_base_url(port), path))""", text)

text = re.sub(
    r"async fn http_post_json_auth\(path: &str, body: serde_json::Value, token: &str\) -> reqwest::Response \{[\s\S]*?post\(format!\(\"\{\}\{\}\", kelan_base_url\(\), path\)\)",
    """async fn http_post_json_auth(port: u16, path: &str, body: serde_json::Value, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}{}", kelan_base_url(port), path))""", text)

text = re.sub(
    r"async fn get_auth_token\(\) -> Option<String> \{",
    """async fn get_auth_token(port: u16) -> Option<String> {""", text)

text = text.replace('http_post_json(\n        "/api/auth/signup"', 'http_post_json(\n        port,\n        "/api/auth/signup"')
text = text.replace('http_post_json(\n        "/api/auth/signin"', 'http_post_json(\n        port,\n        "/api/auth/signin"')
text = text.replace('"email": "integration@test.kelan",\n            "password": "IntegrationTest123!"', '"email": "test@kelan.dev",\n            "password": "KelanTest#2024!"')


# Now update the tests to call spawn_test_server().await and pass port
# 1. ensure_server_running().await; -> let (port, _svr) = spawn_test_server().await;
text = text.replace("ensure_server_running().await;", "let (port, _svr) = spawn_test_server().await;")

# 2. http_get("/api/...") -> http_get(port, "/api/...")
text = text.replace('http_get("/api/', 'http_get(port, "/api/')
text = text.replace('http_get("/api/stats")', 'http_get(port, "/api/stats")')

# 3. http_post_json("/api/...") -> http_post_json(port, "/api/...")
text = text.replace('http_post_json(\n            "/api/', 'http_post_json(\n            port,\n            "/api/')

# 4. format!("{}/api/entities", kelan_base_url()) -> format!("{}/api/entities", kelan_base_url(port))
text = text.replace("kelan_base_url()", "kelan_base_url(port)")

# 5. get_auth_token().await -> get_auth_token(port).await
text = text.replace("get_auth_token().await", "get_auth_token(port).await")

with open('/Users/wopsy/programming/Project/kelan-core/aitp-server/tests/integration_tests.rs', 'w') as f:
    f.write(text)

