use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashSet;
use strum::{Display, EnumString};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Permission {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum PermissionKey {
    #[strum(serialize = "connection:read")]
    ConnectionRead,
    #[strum(serialize = "connection:write")]
    ConnectionWrite,
    #[strum(serialize = "connection:delete")]
    ConnectionDelete,
    #[strum(serialize = "query:execute")]
    QueryExecute,
    #[strum(serialize = "query:history:read")]
    QueryHistoryRead,
    #[strum(serialize = "saved_sql:read")]
    SavedSqlRead,
    #[strum(serialize = "saved_sql:write")]
    SavedSqlWrite,
    #[strum(serialize = "ai:use")]
    AiUse,
    #[strum(serialize = "settings:read")]
    SettingsRead,
    #[strum(serialize = "settings:write")]
    SettingsWrite,
    #[strum(serialize = "user:manage")]
    UserManage,
    #[strum(serialize = "admin")]
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum RoleKey {
    Viewer,
    Editor,
    Admin,
}

impl RoleKey {
    pub fn permissions(&self) -> HashSet<PermissionKey> {
        match self {
            RoleKey::Viewer => HashSet::from([
                PermissionKey::ConnectionRead,
                PermissionKey::QueryHistoryRead,
                PermissionKey::SavedSqlRead,
                PermissionKey::AiUse,
            ]),
            RoleKey::Editor => {
                let mut perms = RoleKey::Viewer.permissions();
                perms.extend([
                    PermissionKey::ConnectionWrite,
                    PermissionKey::QueryExecute,
                    PermissionKey::SavedSqlWrite,
                ]);
                perms
            }
            RoleKey::Admin => {
                let mut perms = RoleKey::Editor.permissions();
                perms.extend([
                    PermissionKey::ConnectionDelete,
                    PermissionKey::SettingsRead,
                    PermissionKey::SettingsWrite,
                    PermissionKey::UserManage,
                    PermissionKey::Admin,
                ]);
                perms
            }
        }
    }
}
