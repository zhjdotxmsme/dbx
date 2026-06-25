use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::Session;

#[derive(Clone)]
pub struct SessionRepository {
    pub pool: PgPool,
}

impl SessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, session: &Session) -> Result<Session> {
        let created = sqlx::query_as!(
            Session,
            r#"
            INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at, last_active_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, user_id, token, expires_at, ip_address, user_agent, created_at, last_active_at
            "#,
            session.id,
            session.user_id,
            session.token,
            session.expires_at,
            session.ip_address,
            session.user_agent,
            session.created_at,
            session.last_active_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(created)
    }

    pub async fn find_by_token(&self, token: &str) -> Result<Option<Session>> {
        let session = sqlx::query_as!(
            Session,
            r#"
            SELECT id, user_id, token, expires_at, ip_address, user_agent, created_at, last_active_at
            FROM sessions
            WHERE token = $1
            "#,
            token
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    pub async fn delete_by_token(&self, token: &str) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM sessions
            WHERE token = $1
            "#,
            token
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_last_active(&self, token: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET last_active_at = NOW()
            WHERE token = $1
            "#,
            token
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_expired(&self) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM sessions
            WHERE expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_by_user_id(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM sessions
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn find_all_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let sessions = sqlx::query_as!(
            Session,
            r#"
            SELECT id, user_id, token, expires_at, ip_address, user_agent, created_at, last_active_at
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }
}
