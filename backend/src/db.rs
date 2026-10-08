use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};

use crate::entities::{ip_blacklist, threats};
use crate::types::{Threat, ThreatInput, now_ms_f64, now_ms_i64, normalize_severity};

/// Create the SOC persistence schema if it does not exist yet.
pub async fn init_tables(db: &DatabaseConnection) -> Result<(), String> {
    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            frontend_id INTEGER NOT NULL DEFAULT 0,
            ts_ms       REAL NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'medium',
            rule_id     TEXT NOT NULL DEFAULT '',
            rule_name   TEXT NOT NULL DEFAULT '',
            ip          TEXT NOT NULL DEFAULT '',
            payload     TEXT NOT NULL DEFAULT '',
            origin      TEXT NOT NULL DEFAULT '',
            received_at INTEGER NOT NULL
        );",
    )
    .await?;

    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip       TEXT PRIMARY KEY,
            reason   TEXT NOT NULL DEFAULT '',
            added_at INTEGER NOT NULL
        );",
    )
    .await?;

    Ok(())
}

async fn run_sql(db: &DatabaseConnection, sql: &str) -> Result<(), String> {
    db.execute(sea_orm::Statement::from_string(db.get_database_backend(), sql.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Cheap liveness check of the underlying connection.
pub async fn ping(db: &DatabaseConnection) -> Result<(), String> {
    run_sql(db, "SELECT 1").await
}

fn to_threat(row: threats::Model) -> Threat {
    Threat {
        id: row.id as i64,
        frontend_id: row.frontend_id as u64,
        ts_ms: row.ts_ms,
        severity: row.severity,
        rule_id: row.rule_id,
        rule_name: row.rule_name,
        ip: row.ip,
        payload: row.payload,
        origin: row.origin,
        received_at: row.received_at,
    }
}

/// Persist a reported threat. `ts_ms` defaults to server time when the client
/// left it at 0. Returns the assigned database row id.
pub async fn insert_threat(db: &DatabaseConnection, input: &ThreatInput) -> Result<i64, String> {
    let row = threats::ActiveModel {
        id: NotSet, // SQLite AUTOINCREMENT assigns it
        frontend_id: Set(input.id as i64),
        ts_ms: Set(if input.ts_ms > 0.0 { input.ts_ms } else { now_ms_f64() }),
        severity: Set(normalize_severity(&input.severity)),
        rule_id: Set(input.rule_id.clone()),
        rule_name: Set(input.rule_name.clone()),
        ip: Set(input.ip.clone()),
        payload: Set(input.payload.clone()),
        origin: Set(input.origin.clone()),
        received_at: Set(now_ms_i64()),
    };

    let inserted = row.insert(db).await.map_err(|e| e.to_string())?;
    Ok(inserted.id as i64)
}

/// Most recent threats first. `severity` (if given) must be canonical
/// `low|medium|high|critical`.
pub async fn list_threats(
    db: &DatabaseConnection,
    limit: u64,
    severity: Option<&str>,
) -> Result<Vec<Threat>, String> {
    let mut query = threats::Entity::find().order_by_desc(threats::Column::Id);

    if let Some(sev) = severity {
        query = query.filter(threats::Column::Severity.eq(sev));
    }

    let rows = query.limit(limit).all(db).await.map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_threat).collect())
}

/// Fetch a single threat by its database row id.
pub async fn find_threat(db: &DatabaseConnection, id: i64) -> Result<Option<Threat>, String> {
    let row = threats::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(row.map(to_threat))
}

/// Idempotently add an IP to the persisted blocklist: inserts on first use,
/// refreshes the reason/timestamp on repeats.
pub async fn upsert_blacklist(
    db: &DatabaseConnection,
    ip: &str,
    reason: &str,
) -> Result<(), String> {
    let existing = ip_blacklist::Entity::find_by_id(ip.to_string())
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let now = now_ms_i64();
    if let Some(model) = existing {
        let mut active: ip_blacklist::ActiveModel = model.into();
        active.reason = Set(reason.to_string());
        active.added_at = Set(now);
        active.update(db).await.map_err(|e| e.to_string())?;
    } else {
        ip_blacklist::ActiveModel {
            ip: Set(ip.to_string()),
            reason: Set(reason.to_string()),
            added_at: Set(now),
        }
        .insert(db)
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}