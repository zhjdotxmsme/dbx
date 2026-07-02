use std::sync::Arc;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashSet;
use uuid::Uuid;

use crate::auth::{AuthCheckResponse, AuthService};
use crate::error::AppError;
use crate::models::PermissionKey;
use crate::state::WebState;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: uuid::Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub permissions: HashSet<PermissionKey>,
    pub roles: Vec<String>,
}

pub async fn auth_middleware<B>(
    state: axum::extract::State<Arc<WebState>>,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    let auth_required = state.auth_service.is_some();

    if !auth_required {
        return next.run(request).await;
    }

    let auth_service = state.auth_service.as_ref().unwrap();

    let session_token = extract_session_token(&request);

    if let Some(token) = session_token {
        if let Ok(Some(user)) = auth_service.validate_session(&token).await {
            let permissions = auth_service.get_user_permissions(user.id).await.unwrap_or_default();
            let roles = auth_service.get_user_roles(user.id).await.unwrap_or_default();

            let authenticated_user = AuthenticatedUser {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                permissions,
                roles,
            };

            request.extensions_mut().insert(authenticated_user);
            return next.run(request).await;
        }
    }

    if request.uri().path().starts_with("/api/auth/") {
        return next.run(request).await;
    }

    if !request.uri().path().starts_with("/api/") {
        return next.run(request).await;
    }

    StatusCode::UNAUTHORIZED.into_response()
}

fn extract_session_token<B>(request: &Request<B>) -> Option<String> {
    let cookie_header = request.headers().get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?;

    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("dbx_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

pub struct RequirePermission(pub PermissionKey);

#[async_trait]
impl<S, B> FromRequestParts<S> for RequirePermission
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<AuthenticatedUser>()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if user.permissions.contains(&self.0) || user.permissions.contains(&PermissionKey::Admin) {
            Ok(Self(self.0))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Resolves user_id filter and audit target for per-user data routes.
///
/// Returns `(filter, audit_target)` where:
/// - `filter`: `Some(uid)` → `WHERE user_id = ?`, `None` → admin "see all"
/// - `audit_target`: `Some(Uuid)` → write audit_log, `None` → regular access
pub fn resolve_user_filter(
    user: &AuthenticatedUser,
    as_user: Option<&str>,
    all: bool,
) -> Result<(Option<String>, Option<Uuid>), AppError> {
    let is_admin = user.permissions.contains(&PermissionKey::Admin);

    let as_user_id = match as_user {
        Some(raw) => {
            if !is_admin {
                return Err(AppError(anyhow::anyhow!("Only admin can use as_user")));
            }
            let uid = raw.parse::<Uuid>().map_err(|_| {
                AppError(anyhow::anyhow!("Invalid as_user UUID: {}", raw))
            })?;
            Some(uid)
        }
        None => None,
    };

    // Admin flow
    if let Some(target) = as_user_id {
        return Ok((Some(target.to_string()), Some(target)));
    }
    if all && is_admin {
        return Ok((None, None));
    }
    if is_admin {
        return Ok((Some(user.id.to_string()), None));
    }
    // Non-admin: always filter by own id
    Ok((Some(user.id.to_string()), None))
}
