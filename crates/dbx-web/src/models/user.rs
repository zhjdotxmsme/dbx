use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub ldap_dn: Option<String>,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub is_local_admin: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ldap_dn: None,
            username,
            display_name: None,
            email: None,
            is_local_admin: false,
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_ldap_dn(mut self, ldap_dn: String) -> Self {
        self.ldap_dn = Some(ldap_dn);
        self
    }

    pub fn with_display_name(mut self, display_name: String) -> Self {
        self.display_name = Some(display_name);
        self
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn as_local_admin(mut self) -> Self {
        self.is_local_admin = true;
        self
    }
}
