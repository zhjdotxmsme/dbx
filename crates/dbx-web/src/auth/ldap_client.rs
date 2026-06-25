use std::time::Duration;

use anyhow::{Context, Result};
use bb8::Pool;
use ldap3::adapters::{Adapter, LdapConnAdapter};
use ldap3::{ldap_escape, LdapConnSettings, Scope, SearchEntry};
use tracing::{debug, error, info};

use crate::config::LdapConfig;

#[derive(Debug, Clone)]
pub struct LdapUser {
    pub dn: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
}

pub struct LdapAuthClient {
    pool: Pool<LdapConnectionManager>,
    settings: LdapConnSettings,
    config: LdapConfig,
}

impl Clone for LdapAuthClient {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            settings: self.settings.clone(),
            config: self.config.clone(),
        }
    }
}

pub struct LdapConnectionManager {
    url: String,
    settings: LdapConnSettings,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
}

#[async_trait::async_trait]
impl bb8::ManageConnection for LdapConnectionManager {
    type Connection = LdapConnAdapter;
    type Error = ldap3::LdapError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut conn = ldap3::Ldap::with_settings(&self.url, self.settings.clone()).await?;
        conn.simple_bind(&self.bind_dn, &self.bind_password).await?;
        Ok(conn)
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.simple_bind(&self.bind_dn, &self.bind_password).await?;
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

impl LdapAuthClient {
    pub async fn new(config: LdapConfig) -> Result<Self> {
        let settings = LdapConnSettings::new()
            .set_starttls(config.tls_enabled)
            .set_no_tls_verify(config.tls_insecure)
            .set_connect_timeout(Some(Duration::from_secs(config.connect_timeout_secs)));

        let manager = LdapConnectionManager {
            url: config.url.clone(),
            settings: settings.clone(),
            bind_dn: config.bind_dn.clone(),
            bind_password: config.bind_password.clone(),
            base_dn: config.base_dn.clone(),
        };

        let pool = Pool::builder()
            .max_size(config.max_pool_size)
            .min_idle(Some(2))
            .connection_timeout(Duration::from_secs(config.connect_timeout_secs))
            .build(manager)
            .await
            .context("Failed to create LDAP connection pool")?;

        info!("LDAP client initialized with URL: {}", config.url);

        Ok(Self { pool, settings, config })
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<LdapUser>> {
        debug!("Attempting LDAP authentication for user: {}", username);

        let escaped_username = ldap_escape(username);
        let filter = self
            .config
            .user_filter_template
            .replace("{username}", &escaped_username);

        debug!("LDAP search filter: {}", filter);

        let mut conn = self
            .pool
            .get()
            .await
            .context("Failed to get LDAP connection from pool")?;

        let (entries, _) = conn
            .search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter,
                vec!["dn", "cn", "mail", "uid", "sAMAccountName", "memberOf"],
            )
            .await
            .context("LDAP search failed")?;

        if entries.is_empty() {
            debug!("No LDAP user found for username: {}", username);
            return Ok(None);
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        let user_dn = entry.dn.clone();

        debug!("Found LDAP user: {}", user_dn);

        // Create a dedicated connection for user credential verification.
        // This avoids mutating the pooled connection's auth state.
        let mut user_conn = ldap3::Ldap::with_settings(&self.config.url, self.settings.clone())
            .await
            .map_err(|e| {
                error!("Failed to create LDAP connection for user bind: {}", e);
                e
            })?;

        let bind_result = user_conn.simple_bind(&user_dn, password).await;

        match bind_result {
            Ok(result) if result.rc == 0 => {
                debug!("LDAP authentication successful for user: {}", username);

                let mut groups = entry
                    .attrs
                    .get("memberOf")
                    .cloned()
                    .unwrap_or_default();

                // Fallback: if the server does not support the memberOf overlay
                // (e.g. plain OpenLDAP without the memberof module), search for
                // groups where this user is listed as a member.
                if groups.is_empty() {
                    if let Some(ref group_search_base) = self.config.group_search_base {
                        debug!("memberOf attribute not found, searching groups in {}", group_search_base);
                        let group_filter = format!("(&(objectClass=groupOfNames)(member={}))", ldap_escape(&user_dn));
                        if let Ok((group_entries, _)) = conn
                            .search(
                                group_search_base,
                                Scope::Subtree,
                                &group_filter,
                                vec!["dn"],
                            )
                            .await
                        {
                            for group_entry in group_entries {
                                let parsed = SearchEntry::construct(group_entry);
                                groups.push(parsed.dn);
                            }
                        }
                    }
                }

                let actual_username = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .or_else(|| entry.attrs.get("uid").and_then(|v| v.first()))
                    .cloned()
                    .unwrap_or_else(|| username.to_string());

                let display_name = entry
                    .attrs
                    .get("cn")
                    .and_then(|v| v.first())
                    .cloned();

                let email = entry
                    .attrs
                    .get("mail")
                    .and_then(|v| v.first())
                    .cloned();

                Ok(Some(LdapUser {
                    dn: user_dn,
                    username: actual_username,
                    display_name,
                    email,
                    groups,
                }))
            }
            Ok(result) => {
                debug!(
                    "LDAP authentication failed for user: {}, error code: {}",
                    username, result.rc
                );
                Ok(None)
            }
            Err(e) => {
                error!("LDAP bind error for user {}: {}", username, e);
                Ok(None)
            }
        }
    }

    pub fn get_config(&self) -> &LdapConfig {
        &self.config
    }
}
