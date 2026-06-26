use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashSet;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::models::{PermissionKey, RoleKey, User};
use crate::repositories::{AppConfigRepository, SessionRepository, UserRepository};

use super::ldap_client::LdapAuthClient;
use super::session_manager::SessionManager;

pub struct AuthService {
    user_repo: UserRepository,
    session_repo: SessionRepository,
    app_config_repo: AppConfigRepository,
    ldap_client: Option<Arc<LdapAuthClient>>,
    session_manager: SessionManager,
    config: AppConfig,
    rate_limit: Arc<std::sync::Mutex<RateLimitState>>,
}

struct RateLimitState {
    fail_count: u32,
    locked_until: Option<std::time::Instant>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            fail_count: 0,
            locked_until: None,
        }
    }
}

const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: u64 = 60;

impl AuthService {
    pub fn new(
        pool: PgPool,
        ldap_client: Option<Arc<LdapAuthClient>>,
        config: AppConfig,
    ) -> Self {
        let user_repo = UserRepository::new(pool.clone());
        let session_repo = SessionRepository::new(pool.clone());
        let app_config_repo = AppConfigRepository::new(pool);
        let session_manager = SessionManager::new(config.jwt.secret.clone());

        Self {
            user_repo,
            session_repo,
            app_config_repo,
            ldap_client,
            session_manager,
            config,
            rate_limit: Arc::new(std::sync::Mutex::new(RateLimitState::default())),
        }
    }

    pub async fn login(&self, username: Option<&str>, password: &str) -> Result<Option<(User, String)>> {
        {
            let mut rl = self.rate_limit.lock().unwrap();
            if let Some(locked_until) = rl.locked_until {
                if locked_until > std::time::Instant::now() {
                    let remaining = (locked_until - std::time::Instant::now()).as_secs();
                    anyhow::bail!("Rate limited. Please try again in {} seconds", remaining);
                }
            }
        }

        let username = username.unwrap_or("admin");

        if let Some(ldap_client) = &self.ldap_client {
            debug!("Attempting LDAP authentication for user: {}", username);
            match ldap_client.authenticate(username, password).await {
                Ok(Some(ldap_user)) => {
                    info!("LDAP authentication successful for user: {}", username);
                    let user = self.get_or_create_ldap_user(&ldap_user).await?;
                    self.sync_user_roles_from_ldap_groups(user.id, &ldap_user.groups).await?;

                    {
                        let mut rl = self.rate_limit.lock().unwrap();
                        rl.fail_count = 0;
                        rl.locked_until = None;
                    }

                    let session_token = self.create_session(user.id).await?;
                    return Ok(Some((user, session_token)));
                }
                Ok(None) => {
                    debug!("LDAP authentication failed for user: {}", username);
                }
                Err(e) => {
                    error!("LDAP authentication error: {}", e);
                }
            }
        }

        if self.config.local_auth.enabled {
            debug!("Attempting local authentication for user: {}", username);

            if username == "admin" {
                if let Some(local_password_hash) = self.app_config_repo.get_local_password_hash().await? {
                    let parsed_hash = PasswordHash::new(&local_password_hash)
                        .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;

                    if Argon2::default()
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok()
                    {
                        info!("Local authentication successful for user: admin");

                        {
                            let mut rl = self.rate_limit.lock().unwrap();
                            rl.fail_count = 0;
                            rl.locked_until = None;
                        }

                        let user = self.user_repo.create_local_admin_if_not_exists("admin").await?;
                        let session_token = self.create_session(user.id).await?;
                        return Ok(Some((user, session_token)));
                    }
                } else if let Some(env_password) = &self.config.local_auth.password {
                    if password == env_password {
                        info!("Local authentication successful (env var) for user: admin");

                        {
                            let mut rl = self.rate_limit.lock().unwrap();
                            rl.fail_count = 0;
                            rl.locked_until = None;
                        }

                        let salt = SaltString::generate(&mut OsRng);
                        let hash = Argon2::default()
                            .hash_password(env_password.as_bytes(), &salt)
                            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
                            .to_string();

                        self.app_config_repo.set_local_password_hash(&hash, None).await?;

                        let user = self.user_repo.create_local_admin_if_not_exists("admin").await?;
                        let session_token = self.create_session(user.id).await?;
                        return Ok(Some((user, session_token)));
                    }
                }
            }
        }

        {
            let mut rl = self.rate_limit.lock().unwrap();
            rl.fail_count += 1;
            if rl.fail_count >= MAX_ATTEMPTS {
                rl.locked_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS));
                rl.fail_count = 0;
                warn!("Login rate limit triggered");
            }
        }

        Ok(None)
    }

    async fn get_or_create_ldap_user(&self, ldap_user: &super::ldap_client::LdapUser) -> Result<User> {
        if let Some(user) = self.user_repo.find_by_ldap_dn(&ldap_user.dn).await? {
            let mut updated_user = user;
            let needs_update = updated_user.display_name != ldap_user.display_name
                || updated_user.email != ldap_user.email;

            if needs_update {
                updated_user.display_name = ldap_user.display_name.clone();
                updated_user.email = ldap_user.email.clone();
                self.user_repo.update(&updated_user).await?;
            }

            return Ok(updated_user);
        }

        if let Some(user) = self.user_repo.find_by_username(&ldap_user.username).await? {
            let mut updated_user = user;
            updated_user.ldap_dn = Some(ldap_user.dn.clone());
            updated_user.display_name = ldap_user.display_name.clone();
            updated_user.email = ldap_user.email.clone();
            self.user_repo.update(&updated_user).await?;
            return Ok(updated_user);
        }

        let mut new_user = User::new(ldap_user.username.clone())
            .with_ldap_dn(ldap_user.dn.clone());

        if let Some(display_name) = &ldap_user.display_name {
            new_user = new_user.with_display_name(display_name.clone());
        }
        if let Some(email) = &ldap_user.email {
            new_user = new_user.with_email(email.clone());
        }

        let created_user = self.user_repo.create(&new_user).await?;
        info!("Created new LDAP user: {}", created_user.username);

        Ok(created_user)
    }

    /// Full-sync LDAP group membership to DB roles.
    ///
    /// Computes the difference between the target roles (derived from the user's
    /// current LDAP groups) and the current LDAP-mapped roles in the database,
    /// then adds missing roles and removes stale ones. Non-LDAP roles are never
    /// touched.
    async fn sync_user_roles_from_ldap_groups(&self, user_id: Uuid, groups: &[String]) -> Result<()> {
        // Target: roles mapped from the user's current LDAP groups
        let target_roles: HashSet<String> = groups
            .iter()
            .filter_map(|dn| self.user_repo.find_role_by_ldap_group_dn(dn).await.ok().flatten())
            .map(|r| r.name)
            .collect();

        // Current: LDAP-mapped roles the user already has in the database
        let current_roles: HashSet<String> = self
            .user_repo
            .get_user_ldap_roles(user_id)
            .await?
            .into_iter()
            .map(|r| r.name)
            .collect();

        // Add new roles
        for role in target_roles.difference(&current_roles) {
            self.user_repo.assign_role_by_name(user_id, role).await?;
        }

        // Remove stale roles
        for role in current_roles.difference(&target_roles) {
            self.user_repo.remove_role_by_name(user_id, role).await?;
        }

        Ok(())
    }

    async fn create_session(&self, user_id: Uuid) -> Result<String> {
        let token = Uuid::new_v4().to_string();
        let session = crate::models::Session::new(user_id, token.clone(), self.config.session.ttl_hours);
        self.session_repo.create(&session).await?;
        Ok(token)
    }

    pub async fn validate_session(&self, token: &str) -> Result<Option<User>> {
        let session = match self.session_repo.find_by_token(token).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        if session.is_expired() {
            self.session_repo.delete_by_token(token).await?;
            return Ok(None);
        }

        self.session_repo.update_last_active(token).await?;

        let user = self.user_repo.find_by_id(session.user_id).await?;
        Ok(user)
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        self.session_repo.delete_by_token(token).await?;
        Ok(())
    }

    pub async fn get_user_permissions(&self, user_id: Uuid) -> Result<HashSet<PermissionKey>> {
        let permission_names = self.user_repo.get_user_permission_names(user_id).await?;
        let mut permissions = HashSet::new();

        for name in permission_names {
            if let Ok(perm) = name.parse::<PermissionKey>() {
                permissions.insert(perm);
            }
        }

        Ok(permissions)
    }

    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<String>> {
        let roles = self.user_repo.get_user_roles(user_id).await?;
        Ok(roles.into_iter().map(|r| r.name).collect())
    }

    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        if !self.config.local_auth.enabled {
            anyhow::bail!("Local authentication is disabled");
        }

        if new_password.is_empty() {
            anyhow::bail!("New password cannot be empty");
        }

        let current_hash = self.app_config_repo.get_local_password_hash().await?
            .ok_or_else(|| anyhow::anyhow!("No password configured"))?;

        let parsed_hash = PasswordHash::new(&current_hash)
            .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;

        if Argon2::default()
            .verify_password(old_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            anyhow::bail!("Current password is incorrect");
        }

        let salt = SaltString::generate(&mut OsRng);
        let new_hash = Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
            .to_string();

        self.app_config_repo.set_local_password_hash(&new_hash, None).await?;

        info!("Local admin password changed successfully");

        Ok(())
    }

    pub async fn is_password_configured(&self) -> Result<bool> {
        if self.config.local_auth.password.is_some() {
            return Ok(true);
        }

        Ok(self.app_config_repo.get_local_password_hash().await?.is_some())
    }

    pub fn is_ldap_enabled(&self) -> bool {
        self.ldap_client.is_some()
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let deleted = self.session_repo.delete_expired().await?;
        if deleted > 0 {
            debug!("Cleaned up {} expired sessions", deleted);
        }
        Ok(deleted)
    }
}

impl Clone for AuthService {
    fn clone(&self) -> Self {
        Self {
            user_repo: self.user_repo.clone(),
            session_repo: self.session_repo.clone(),
            app_config_repo: self.app_config_repo.clone(),
            ldap_client: self.ldap_client.clone(),
            session_manager: self.session_manager.clone(),
            config: self.config.clone(),
            rate_limit: self.rate_limit.clone(),
        }
    }
}
