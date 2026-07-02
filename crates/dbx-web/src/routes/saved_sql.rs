use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use dbx_core::saved_sql::{SavedSqlFile, SavedSqlFolder, SavedSqlLibrary};
use serde::Deserialize;

use crate::audit;
use crate::auth::middleware::{resolve_user_filter, AuthenticatedUser};
use crate::error::AppError;
use crate::state::WebState;

#[derive(Deserialize)]
pub struct SavedSqlQuery {
    pub as_user: Option<String>,
    pub all: Option<bool>,
}

pub async fn load_saved_sql_library(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Query(q): Query<SavedSqlQuery>,
) -> Result<Json<SavedSqlLibrary>, AppError> {
    let (filter, audit_target) = resolve_user_filter(&user, q.as_user.as_deref(), q.all.unwrap_or(false))?;
    if let Some(target) = audit_target {
        audit::log_audit(&state.pg_pool, user.id, "list_user_saved_sql", Some(target), None, None, None).await;
    }
    let library = state.app.storage.load_saved_sql_library(filter.as_deref()).await.map_err(AppError)?;
    Ok(Json(library))
}

pub async fn load_saved_sql_file(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<Option<SavedSqlFile>>, AppError> {
    let file = state.app.storage.load_saved_sql_file(&id, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(file))
}

pub async fn save_saved_sql_folder(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Json(folder): Json<SavedSqlFolder>,
) -> Result<Json<SavedSqlFolder>, AppError> {
    state.app.storage.save_saved_sql_folder(&folder, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(folder))
}

pub async fn delete_saved_sql_folder(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    state.app.storage.delete_saved_sql_folder(&id, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(()))
}

pub async fn save_saved_sql_file(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Json(file): Json<SavedSqlFile>,
) -> Result<Json<SavedSqlFile>, AppError> {
    state.app.storage.save_saved_sql_file(&file, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(file))
}

pub async fn delete_saved_sql_file(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    state.app.storage.delete_saved_sql_file(&id, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(()))
}
