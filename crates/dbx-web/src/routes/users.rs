use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{PermissionKey, User};
use crate::state::WebState;

#[derive(Serialize)]
pub struct UserEntry {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub is_active: bool,
    pub roles: Vec<String>,
}

pub async fn list_users(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<UserEntry>>, AppError> {
    if !user.permissions.contains(&PermissionKey::UserManage) && !user.permissions.contains(&PermissionKey::Admin) {
        return Err(AppError(anyhow::anyhow!("Forbidden: requires user:manage permission")));
    }
    let users = sqlx::query_as!(
        User,
        r#"SELECT id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at FROM users ORDER BY username"#
    )
    .fetch_all(&state.pg_pool)
    .await?;

    let mut entries = Vec::new();
    for u in users {
        let roles = state.user_repo.get_user_roles(u.id).await?.into_iter().map(|r| r.name).collect();
        entries.push(UserEntry {
            id: u.id,
            username: u.username,
            display_name: u.display_name,
            email: u.email,
            is_active: u.is_active,
            roles,
        });
    }
    Ok(Json(entries))
}

#[derive(Deserialize)]
pub struct AssignRoleRequest {
    pub role_name: String,
}

pub async fn assign_role(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AssignRoleRequest>,
) -> Result<Json<()>, AppError> {
    if !user.permissions.contains(&PermissionKey::UserManage) && !user.permissions.contains(&PermissionKey::Admin) {
        return Err(AppError(anyhow::anyhow!("Forbidden")));
    }
    state.user_repo.assign_role_by_name(user_id, &body.role_name).await?;
    Ok(Json(()))
}

pub async fn remove_role(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path((user_id, role_name)): Path<(Uuid, String)>,
) -> Result<Json<()>, AppError> {
    if !user.permissions.contains(&PermissionKey::UserManage) && !user.permissions.contains(&PermissionKey::Admin) {
        return Err(AppError(anyhow::anyhow!("Forbidden")));
    }
    state.user_repo.remove_role_by_name(user_id, &role_name).await?;
    Ok(Json(()))
}
