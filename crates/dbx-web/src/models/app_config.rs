use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AppConfigEntry {
    pub key: String,
    pub value: String,
    pub encrypted: bool,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl AppConfigEntry {
    pub fn new(key: String, value: String) -> Self {
        Self {
            key,
            value,
            encrypted: false,
            updated_at: Utc::now(),
            updated_by: None,
        }
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn with_updated_by(mut self, updated_by: Uuid) -> Self {
        self.updated_by = Some(updated_by);
        self
    }
}
