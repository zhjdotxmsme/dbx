use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthenticatedUser;
use crate::error::AppError;
use crate::models::PermissionKey;
use crate::state::WebState;

#[derive(Deserialize)]
pub struct GrantRequest {
    pub role_id: Uuid,
    pub connection_id: String,
}

#[derive(Deserialize)]
pub struct RoleConnectionsQuery {
    pub role_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct RoleConnectionsResponse {
    pub role_id: Uuid,
    pub connection_ids: Vec<String>,
}

fn require_user_manage(user: &AuthenticatedUser) -> Result<(), AppError> {
    if user.permissions.contains(&PermissionKey::UserManage) || user.permissions.contains(&PermissionKey::Admin) {
        Ok(())
    } else {
        Err(AppError(anyhow::anyhow!("Forbidden: requires user:manage permission")))
    }
}

pub async fn grant(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Json(body): Json<GrantRequest>,
) -> Result<Json<()>, AppError> {
    require_user_manage(&user)?;
    state.user_repo.grant_connection_to_role(body.role_id, &body.connection_id, None).await?;
    Ok(Json(()))
}

pub async fn revoke(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Json(body): Json<GrantRequest>,
) -> Result<Json<()>, AppError> {
    require_user_manage(&user)?;
    state.user_repo.revoke_connection_from_role(body.role_id, &body.connection_id).await?;
    Ok(Json(()))
}

pub async fn list_for_role(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Query(q): Query<RoleConnectionsQuery>,
) -> Result<Json<RoleConnectionsResponse>, AppError> {
    require_user_manage(&user)?;
    let role_id = q.role_id.ok_or_else(|| AppError(anyhow::anyhow!("role_id required")))?;
    let connection_ids = state.user_repo.list_role_connections(role_id).await?;
    Ok(Json(RoleConnectionsResponse { role_id, connection_ids }))
}
