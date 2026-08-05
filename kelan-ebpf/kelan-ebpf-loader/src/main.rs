use kelan_ebpf_loader::EbpfLoader;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
struct Command {
    action: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    entity_id: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
}

fn parse_session_id(sid: &str) -> u64 {
    if let Ok(val) = sid.parse::<u64>() {
        val
    } else {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        sid.hash(&mut hasher);
        hasher.finish()
    }
}

fn parse_ipv4(ip_str: &str) -> Option<u32> {
    let addr: std::net::Ipv4Addr = ip_str.parse().ok()?;
    Some(u32::from(addr))
}

fn main() {
    let mut interface = "eth0".to_string();
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--interface" && i + 1 < args.len() {
            interface = args[i + 1].clone();
        }
    }

    let bpf_obj_path = if std::path::Path::new("kelan_xdp.o").exists() {
        PathBuf::from("kelan_xdp.o")
    } else {
        PathBuf::from("/usr/lib/kelan/kelan_xdp.o")
    };

    let loader = match EbpfLoader::load_and_attach(&interface, &bpf_obj_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to initialize EbpfLoader: {:?}", e);
            return;
        }
    };

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Ok(cmd) = serde_json::from_str::<Command>(&line) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Run periodic cleanup
            let _ = loader.cleanup_expired(now);

            match cmd.action.as_str() {
                "PERMIT" => {
                    let sid = cmd.session_id.as_deref().unwrap_or("");
                    let session_id_u64 = parse_session_id(sid);
                    let ip_str = cmd.src_ip.as_deref().unwrap_or("127.0.0.1");
                    let src_ip = parse_ipv4(ip_str).unwrap_or(0x7f000001);
                    // 5 minutes TTL
                    let expiry = now + 300;

                    if let Err(e) = loader.permit_session(session_id_u64, src_ip, 0, expiry) {
                        eprintln!("Error executing PERMIT session: {:?}", e);
                    } else {
                        eprintln!("eBPF successfully permitted session {}", sid);
                    }
                }
                "REVOKE" => {
                    // Revocation is mapped to deny_ip or removing the session permit.
                    // If we have src_ip, block it. If we have entity_id, we can block it too.
                    let ip_str = cmd.src_ip.as_deref().unwrap_or("127.0.0.1");
                    let src_ip = parse_ipv4(ip_str).unwrap_or(0x7f000001);
                    // Block for 1 hour
                    let block_until = now + 3600;

                    if let Err(e) = loader.deny_ip(src_ip, block_until) {
                        eprintln!("Error executing REVOKE for IP: {:?}", e);
                    } else {
                        eprintln!("eBPF successfully blacklisted IP {}", ip_str);
                    }
                }
                _ => {
                    eprintln!("Loader received unknown action: {}", cmd.action);
                }
            }
        }
    }
}
