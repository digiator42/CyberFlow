use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sea_orm::DatabaseConnection;

use crate::logstore::LogStore;

/// Application-wide shared state, registered once into the GritShield DI
/// container (`AutoWire::component(AppState)`) and resolved on demand by
/// handlers, middlewares and MCP tools via [`resolve`].
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseConnection>,
    pub store: Arc<LogStore>,
    /// When `Some`, requests must present `X-API-Key` (or `?api_key=`) matching
    /// this value. `None` leaves the API open, which is the frontend default.
    pub api_key: Option<String>,
    /// Live, in-memory IP blocklist consulted by the middleware. Kept in sync
    /// with the persisted `ip_blacklist` table.
    pub blacklist: Arc<Mutex<HashSet<String>>>,
}

/// Resolve the registered application state from the global container.
pub fn resolve() -> Arc<AppState> {
    use gritshield::core::ioc::CONTEXT;
    CONTEXT
        .resolve::<AppState>()
        .expect("AppState was not registered; this must be the first boot step")
}