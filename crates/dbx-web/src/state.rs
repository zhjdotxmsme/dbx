use dbx_core::connection::AppState;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::auth::AuthService;
use crate::config::AppConfig;

#[derive(Debug)]
pub struct LoginRateLimit {
    pub fail_count: u32,
    pub locked_until: Option<std::time::Instant>,
}

impl Default for LoginRateLimit {
    fn default() -> Self {
        Self {
            fail_count: 0,
            locked_until: None,
        }
    }
}

pub struct WebState {
    pub app: Arc<AppState>,
    pub data_dir: PathBuf,
    pub password_disabled: bool,
    pub password_hash: RwLock<Option<String>>,
    pub sessions: RwLock<HashSet<String>>,
    pub sse_channels: RwLock<HashMap<String, broadcast::Sender<String>>>,
    pub sql_file_executions: RwLock<HashMap<String, CancellationToken>>,
    pub login_rate_limit: Mutex<LoginRateLimit>,
    pub export_files: RwLock<HashMap<String, (String, String)>>,
    pub pg_pool: PgPool,
    pub auth_service: Option<Arc<AuthService>>,
    pub config: Arc<AppConfig>,
}

impl WebState {
    pub async fn remove_sse_channel(&self, id: &str) {
        self.sse_channels.write().await.remove(id);
    }
}
