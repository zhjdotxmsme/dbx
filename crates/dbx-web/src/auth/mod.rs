pub mod ldap_client;
pub mod auth_service;
pub mod middleware;
pub mod session_manager;

pub use auth_service::AuthService;
pub use ldap_client::LdapAuthClient;
pub use session_manager::SessionManager;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::WebState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: Option<String>,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub required: bool,
    pub setup_required: bool,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub ok: bool,
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

pub async fn login(
    State(state): State<Arc<WebState>>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let auth_service = match &state.auth_service {
        Some(service) => service,
        None => {
            let hash_guard = state.password_hash.read().await;
            let hash_str = match hash_guard.as_deref() {
                Some(h) => h.to_string(),
                None => {
                    return (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"ok": true})),
                    )
                        .into_response();
                }
            };
            drop(hash_guard);

            let parsed_hash = match argon2::PasswordHash::new(&hash_str) {
                Ok(h) => h,
                Err(_) => {
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Invalid password hash"})),
                    )
                        .into_response();
                }
            };

            if argon2::Argon2::default()
                .verify_password(body.password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }

            let token = uuid::Uuid::new_v4().to_string();
            state.sessions.write().await.insert(token.clone());

            let secure_flag = if state.config.server.secure_cookie { "Secure; " } else { "" };
            let cookie = format!("dbx_session={token}; Path=/; HttpOnly; {secure_flag}SameSite=Lax");
            return (
                axum::http::StatusCode::OK,
                [(axum::http::header::SET_COOKIE, cookie)],
                Json(serde_json::json!({"ok": true})),
            )
                .into_response();
        }
    };

    let username = body.username.as_deref().unwrap_or("admin");

    match auth_service.login(Some(username), &body.password).await {
        Ok(Some((user, session_token))) => {
            let roles = auth_service
                .get_user_roles(user.id)
                .await
                .unwrap_or_default();
            let permissions = auth_service
                .get_user_permissions(user.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.to_string())
                .collect();

            let secure_flag = if state.config.server.secure_cookie { "Secure; " } else { "" };
            let cookie = format!("dbx_session={session_token}; Path=/; HttpOnly; {secure_flag}SameSite=Lax");

            (
                axum::http::StatusCode::OK,
                [(axum::http::header::SET_COOKIE, cookie)],
                Json(LoginResponse {
                    ok: true,
                    user: Some(UserInfo {
                        id: user.id.to_string(),
                        username: user.username,
                        display_name: user.display_name,
                        email: user.email,
                        roles,
                        permissions,
                    }),
                }),
            )
                .into_response()
        }
        Ok(None) => axum::http::StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            tracing::error!("Login error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal server error"})),
            )
                .into_response()
        }
    }
}

pub async fn check(State(state): State<Arc<WebState>>) -> Json<AuthCheckResponse> {
    if state.password_disabled {
        return Json(AuthCheckResponse {
            authenticated: true,
            required: false,
            setup_required: false,
        });
    }

    let has_password = if let Some(auth_service) = &state.auth_service {
        auth_service.is_password_configured().await.unwrap_or(false)
    } else {
        state.password_hash.read().await.is_some()
    };

    if !has_password {
        return Json(AuthCheckResponse {
            authenticated: false,
            required: false,
            setup_required: true,
        });
    }

    Json(AuthCheckResponse {
        authenticated: false,
        required: true,
        setup_required: false,
    })
}

pub async fn setup(
    State(state): State<Arc<WebState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Response, axum::http::StatusCode> {
    if state.password_disabled {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    if let Some(auth_service) = &state.auth_service {
        if auth_service.is_password_configured().await.unwrap_or(false) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }

        if body.password.is_empty() {
            return Err(axum::http::StatusCode::BAD_REQUEST);
        }

        return Ok((
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"ok": true})),
        )
            .into_response());
    }

    if state.password_hash.read().await.is_some() {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    if body.password.is_empty() {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    state
        .app
        .storage
        .save_password_hash(&hash)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    *state.password_hash.write().await = Some(hash);

    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.write().await.insert(token.clone());

    let secure_flag = if state.config.server.secure_cookie { "Secure; " } else { "" };
    let cookie = format!("dbx_session={token}; Path=/; HttpOnly; {secure_flag}SameSite=Lax");
    Ok((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response())
}

pub async fn change_password(
    State(state): State<Arc<WebState>>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, axum::http::StatusCode> {
    if let Some(auth_service) = &state.auth_service {
        return match auth_service
            .change_password(&body.old_password, &body.new_password)
            .await
        {
            Ok(_) => Ok((
                axum::http::StatusCode::OK,
                Json(serde_json::json!({"ok": true})),
            )
                .into_response()),
            Err(_) => Err(axum::http::StatusCode::UNAUTHORIZED),
        };
    }

    let hash_guard = state.password_hash.read().await;
    let hash_str = match hash_guard.as_deref() {
        Some(h) => h.to_string(),
        None => return Err(axum::http::StatusCode::BAD_REQUEST),
    };
    drop(hash_guard);

    if body.new_password.is_empty() {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    let parsed_hash = argon2::PasswordHash::new(&hash_str)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if argon2::Argon2::default()
        .verify_password(body.old_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let new_hash = argon2::Argon2::default()
        .hash_password(body.new_password.as_bytes(), &salt)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    state
        .app
        .storage
        .save_password_hash(&new_hash)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    *state.password_hash.write().await = Some(new_hash);

    Ok((
        axum::http::StatusCode::OK,
        Json(serde_json::json!({"ok": true})),
    )
        .into_response())
}

pub async fn logout(State(state): State<Arc<WebState>>) -> Response {
    let secure_flag = if state.config.server.secure_cookie { "Secure; " } else { "" };
    let cookie = format!("dbx_session=; Path=/; HttpOnly; {secure_flag}Max-Age=0");
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}
