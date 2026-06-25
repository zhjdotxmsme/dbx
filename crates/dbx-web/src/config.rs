use std::path::PathBuf;

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub ldap: Option<LdapConfig>,
    pub jwt: JwtConfig,
    pub session: SessionConfig,
    pub local_auth: LocalAuthConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    pub enabled: bool,
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub user_search_base: String,
    pub group_search_base: Option<String>,
    pub user_filter_template: String,
    pub tls_enabled: bool,
    pub tls_insecure: bool,
    pub connect_timeout_secs: u64,
    pub max_pool_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    pub ttl_hours: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalAuthConfig {
    pub enabled: bool,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
    pub data_dir: Option<PathBuf>,
    pub static_dir: Option<PathBuf>,
    pub max_upload_mb: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                url: "postgres://localhost:5432/dbx".into(),
                max_connections: 10,
            },
            ldap: None,
            jwt: JwtConfig {
                secret: "this-is-a-secret-key-please-change-in-production-min-32-chars".into(),
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 86400,
            },
            session: SessionConfig {
                ttl_hours: 8,
            },
            local_auth: LocalAuthConfig {
                enabled: true,
                password: None,
            },
            server: ServerConfig {
                port: 4224,
                host: "0.0.0.0".into(),
                data_dir: None,
                static_dir: None,
                max_upload_mb: 1024,
            },
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let mut config = Config::builder();

        config = config
            .add_source(File::with_name("config/default").required(false))
            .add_source(Environment::with_prefix("DBX").separator("_"));

        let config = config.build()?;

        let mut app_config: AppConfig = config.try_deserialize()?;

        if let Some(ref dbx_password) = app_config.local_auth.password {
            if dbx_password.is_empty() {
                app_config.local_auth.password = None;
            }
        }

        Ok(app_config)
    }
}
