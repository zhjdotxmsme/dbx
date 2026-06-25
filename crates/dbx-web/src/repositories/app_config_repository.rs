use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::AppConfigEntry;

#[derive(Clone)]
pub struct AppConfigRepository {
    pool: PgPool,
}

impl AppConfigRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, key: &str) -> Result<Option<AppConfigEntry>> {
        let entry = sqlx::query_as!(
            AppConfigEntry,
            r#"
            SELECT key, value, encrypted, updated_at, updated_by
            FROM app_config
            WHERE key = $1
            "#,
            key
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(entry)
    }

    pub async fn set(&self, key: &str, value: &str, encrypted: bool, updated_by: Option<Uuid>) -> Result<AppConfigEntry> {
        let entry = sqlx::query_as!(
            AppConfigEntry,
            r#"
            INSERT INTO app_config (key, value, encrypted, updated_at, updated_by)
            VALUES ($1, $2, $3, NOW(), $4)
            ON CONFLICT (key) DO UPDATE
            SET value = $2, encrypted = $3, updated_at = NOW(), updated_by = $4
            RETURNING key, value, encrypted, updated_at, updated_by
            "#,
            key,
            value,
            encrypted,
            updated_by
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(entry)
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM app_config
            WHERE key = $1
            "#,
            key
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_all(&self) -> Result<Vec<AppConfigEntry>> {
        let entries = sqlx::query_as!(
            AppConfigEntry,
            r#"
            SELECT key, value, encrypted, updated_at, updated_by
            FROM app_config
            ORDER BY key
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    pub async fn get_local_password_hash(&self) -> Result<Option<String>> {
        let entry = self.get("local_password_hash").await?;
        Ok(entry.map(|e| e.value))
    }

    pub async fn set_local_password_hash(&self, hash: &str, updated_by: Option<Uuid>) -> Result<()> {
        self.set("local_password_hash", hash, true, updated_by).await?;
        Ok(())
    }
}
