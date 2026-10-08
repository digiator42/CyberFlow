use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Persisted security threats reported through `POST /api/v1/threats`.
pub mod threats {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "threats")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub frontend_id: i64,
        pub ts_ms: f64,
        pub severity: String,
        pub rule_id: String,
        pub rule_name: String,
        pub ip: String,
        pub payload: String,
        pub origin: String,
        pub received_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// IP addresses that should be blocked at the middleware layer.
pub mod ip_blacklist {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "ip_blacklist")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub ip: String,
        pub reason: String,
        pub added_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}