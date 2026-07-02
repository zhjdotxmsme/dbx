use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use dbx_core::history::HistoryEntry;
use serde::Deserialize;

use crate::audit;
use crate::auth::middleware::{resolve_user_filter, AuthenticatedUser};
use crate::error::AppError;
use crate::state::WebState;

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub activity_kind: Option<String>,
    pub as_user: Option<String>,
    pub all: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveHistoryRequest {
    pub entry: HistoryEntry,
}

pub async fn save_history(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Json(body): Json<SaveHistoryRequest>,
) -> Result<Json<()>, AppError> {
    state.app.storage.save_history_entry(&body.entry, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(()))
}

pub async fn load_history(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<HistoryEntry>>, AppError> {
    let limit = q.limit.unwrap_or(100);
    let offset = q.offset.unwrap_or(0);
    let (filter, audit_target) = resolve_user_filter(&user, q.as_user.as_deref(), q.all.unwrap_or(false))?;
    if let Some(target) = audit_target {
        audit::log_audit(&state.pg_pool, user.id, "view_user_history", Some(target), None, None, None).await;
    }
    let entries = state.app.storage.load_history_entries(filter.as_deref(), limit, offset, q.activity_kind).await.map_err(AppError)?;
    Ok(Json(entries))
}

pub async fn clear_history(State(state): State<Arc<WebState>>) -> Result<Json<()>, AppError> {
    state.app.storage.clear_history().await.map_err(AppError)?;
    Ok(Json(()))
}

pub async fn delete_history_entry(
    State(state): State<Arc<WebState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    state.app.storage.delete_history_entry(&id, &user.id.to_string()).await.map_err(AppError)?;
    Ok(Json(()))
}
