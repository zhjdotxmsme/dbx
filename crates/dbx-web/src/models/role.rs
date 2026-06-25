use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub ldap_group_dn: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Role {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            ldap_group_dn: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_ldap_group_dn(mut self, ldap_group_dn: String) -> Self {
        self.ldap_group_dn = Some(ldap_group_dn);
        self
    }
}
