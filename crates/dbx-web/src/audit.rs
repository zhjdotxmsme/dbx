use sqlx::PgPool;
use uuid::Uuid;

/// Writes an audit log entry when admin uses ?as_user= or ?all=true.
/// Returns Ok even on DB error — audit failure must not block the main operation.
pub async fn log_audit(
    pool: &PgPool,
    actor_id: Uuid,
    action: &str,
    target_user_id: Option<Uuid>,
    target_resource_id: Option<&str>,
    metadata: Option<serde_json::Value>,
    ip_address: Option<&str>,
) {
    if let Err(e) = try_log_audit(pool, actor_id, action, target_user_id, target_resource_id, metadata, ip_address).await {
        tracing::error!("Audit log write failed (action={}, actor={}): {}", action, actor_id, e);
    }
}

async fn try_log_audit(
    pool: &PgPool,
    actor_id: Uuid,
    action: &str,
    target_user_id: Option<Uuid>,
    target_resource_id: Option<&str>,
    metadata: Option<serde_json::Value>,
    ip_address: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO audit_log (actor_id, action, target_user_id, target_resource_id, metadata_json, ip_address)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(actor_id)
    .bind(action)
    .bind(target_user_id)
    .bind(target_resource_id)
    .bind(metadata)
    .bind(ip_address)
    .execute(pool)
    .await?;
    Ok(())
}
