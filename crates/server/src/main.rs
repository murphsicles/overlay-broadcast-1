//! The `overlay-broadcast-server` binary: boots the blocking HTTP api server, wiring the
//! [`api::ApiService`] boundary to the live node client and the obs metrics/health
//! endpoints. Configuration is read from the environment (fail-fast on invalid config):
//!
//! - `BIND`           — listen address (default `0.0.0.0:8080`).
//! - `NODE_RPC_URL`   — BSV node JSON-RPC URL (optional; enables readiness + submission).
//! - `NODE_RPC_USER` / `NODE_RPC_PASS` — node basic-auth credentials (optional).
//! - `MAX_PAYLOAD` / `RATE_LIMIT` / `RATE_WINDOW` / `OP_TIMEOUT_MS` — boundary limits.
//!
//! Secrets are read from the environment at runtime only; none are baked into the image.
#![forbid(unsafe_code)]

use api::{ApiConfig, ApiService, CallerRegistry};
use bsv::HeaderChain;
use obs::Metrics;
use server::{RealBackend, Router};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("server error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let node = match std::env::var("NODE_RPC_URL") {
        Ok(url) => {
            let user = std::env::var("NODE_RPC_USER").ok();
            let pass = std::env::var("NODE_RPC_PASS").ok();
            Some(node::NodeClient::new(
                &url,
                user.as_deref(),
                pass.as_deref(),
            ))
        }
        Err(_) => None,
    };

    let config = ApiConfig {
        max_payload_bytes: env_usize("MAX_PAYLOAD", 65_536),
        rate_limit_per_window: env_u32("RATE_LIMIT", 100),
        rate_window_secs: env_u64("RATE_WINDOW", 60),
        op_timeout_millis: u128::from(env_u64("OP_TIMEOUT_MS", 5_000)),
    };
    let service = ApiService::new(
        config,
        CallerRegistry::new(),
        HeaderChain::new(0),
        RealBackend::new(reconnect(&node)),
    )
    .map_err(|error| format!("invalid configuration: {error}"))?;
    let metrics = Metrics::new().map_err(|_| "metrics init".to_owned())?;
    let mut router = Router::new(service, metrics, node);

    let http = tiny_http::Server::http(&bind).map_err(|error| format!("bind {bind}: {error}"))?;
    println!("overlay-broadcast-server listening on {bind}");
    for mut request in http.incoming_requests() {
        let method = request.method().as_str().to_owned();
        let path = request.url().split('?').next().unwrap_or("/").to_owned();
        let mut body = Vec::new();
        let _ = request.as_reader().read_to_end(&mut body);
        let reply = router.route(&method, &path, &body, unix_now());
        let header =
            tiny_http::Header::from_bytes(b"Content-Type".as_ref(), reply.content_type.as_bytes())
                .map_err(|()| "header".to_owned())?;
        let response = tiny_http::Response::from_data(reply.body)
            .with_status_code(reply.status)
            .with_header(header);
        let _ = request.respond(response);
    }
    Ok(())
}

// A second node handle for the backend (submission), independent of the readiness handle.
fn reconnect(node: &Option<node::NodeClient>) -> Option<node::NodeClient> {
    if node.is_some() {
        let url = std::env::var("NODE_RPC_URL").ok()?;
        let user = std::env::var("NODE_RPC_USER").ok();
        let pass = std::env::var("NODE_RPC_PASS").ok();
        Some(node::NodeClient::new(
            &url,
            user.as_deref(),
            pass.as_deref(),
        ))
    } else {
        None
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
