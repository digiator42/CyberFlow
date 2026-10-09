mod api;
mod db;
mod entities;
mod logstore;
#[cfg(feature = "mcp")]
mod mcp;
mod middleware;
mod state;
mod types;

use std::sync::Arc;
use std::time::Duration;

use gritshield::core::logger::LogLevel;
use gritshield::database::db::{DbConfig, DbManager};
use gritshield::prelude::*;

use crate::logstore::LogStore;
use crate::middleware::{
    ApiKeyMiddleware, BodyLimitMiddleware, HttpSecurityMiddleware, IpBlacklistMiddleware,
    RateLimitMdlw,
};
use crate::state::AppState;

#[tokio::main]
async fn main() {
    // --- Persistence: file-backed SQLite via the framework's DbManager ---
    let db_url = std::env::var("SOC_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://logs_soc.db?mode=rwc".to_string());
    let db_config = DbConfig {
        url: db_url.clone(),
        max_connections: 5,
        min_connections: 1,
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(300),
    };

    let shared_db = DbManager::connect(db_config)
        .await
        .unwrap_or_else(|e| panic!("failed to connect to database at {db_url}: {e}"));

    db::init_tables(shared_db.as_ref())
        .await
        .expect("failed to initialize SOC schema");

    // --- Shared pipeline state, wired into the DI container ---
    let store = Arc::new(LogStore::new());
    let api_key = std::env::var("SOC_API_KEY").ok().filter(|k| !k.is_empty());

    let app_state = Arc::new(AppState {
        db: shared_db.clone(),
        store: store.clone(),
        api_key,
        blacklist: Default::default(),
    });
    gritshield::core::ioc::AutoWire::component((*app_state).clone());

    // --- Router with the SOC middleware chain (request phase runs in order) ---
    let router = Router::new()
        .mount_logger(LogLevel::Debug)
        .mount_db(shared_db)
        .add_middleware(ApiKeyMiddleware::new(app_state.clone()))
        .add_middleware(IpBlacklistMiddleware::new(app_state.clone()))
        .add_middleware(BodyLimitMiddleware::new(512 * 1024)) // 512 KiB; framework caps the whole request at 1 MiB
        .add_middleware(RateLimitMdlw::new(
            app_state.clone(),
            120,
            Duration::from_secs(60),
        ))
        .add_middleware(HttpSecurityMiddleware::new())
        .route(("/health", HttpMethod::GET, api::health))
        .route(("/api/v1/logs", HttpMethod::POST, api::post_logs))
        .route(("/api/v1/stream", HttpMethod::GET, api::stream))
        .route(("/api/v1/threats", HttpMethod::POST, api::post_threat));

    let host = std::env::var("SOC_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("SOC_PORT").unwrap_or_else(|_| "8010".to_string());

    println!("[logs-soc] SOC backend listening on http://{host}:{port}");
    println!(
        "[logs-soc] MCP surface mounted automatically at http://{host}:{port}/mcp (MCP_HTTP_PREFIX to relocate)"
    );
    println!(
        "[logs-soc] database: {}",
        if db_url.contains("memory") { db_url } else { format!("{db_url} (file)") }
    );

    ignite(&host, &port, router).await;
}