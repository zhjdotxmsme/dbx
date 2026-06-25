use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

impl Session {
    pub fn new(user_id: Uuid, token: String, ttl_hours: u64) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(ttl_hours as i64);
        Self {
            id: Uuid::new_v4(),
            user_id,
            token,
            expires_at,
            ip_address: None,
            user_agent: None,
            created_at: now,
            last_active_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    pub fn update_last_active(&mut self) {
        self.last_active_at = Utc::now();
    }
}
