use anyhow::Result;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::models::{Role, RoleKey, User};

#[derive(Clone)]
pub struct UserRepository {
    pub pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_ldap_dn(&self, ldap_dn: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            FROM users
            WHERE ldap_dn = $1
            "#,
            ldap_dn
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn create(&self, user: &User) -> Result<User> {
        let created = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            "#,
            user.id,
            user.ldap_dn,
            user.username,
            user.display_name,
            user.email,
            user.is_local_admin,
            user.is_active,
            user.created_at,
            user.updated_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(created)
    }

    pub async fn update(&self, user: &User) -> Result<User> {
        let updated = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET ldap_dn = $2, username = $3, display_name = $4, email = $5, is_local_admin = $6, is_active = $7, updated_at = NOW()
            WHERE id = $1
            RETURNING id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            "#,
            user.id,
            user.ldap_dn,
            user.username,
            user.display_name,
            user.email,
            user.is_local_admin,
            user.is_active
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(updated)
    }

    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<Role>> {
        let roles = sqlx::query_as!(
            Role,
            r#"
            SELECT r.id, r.name, r.description, r.ldap_group_dn, r.created_at
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    /// Returns roles that are mapped via ldap_group_dn for this user.
    /// These are the roles that the sync function manages — only roles with
    /// a non-null ldap_group_dn are considered LDAP-managed.
    pub async fn get_user_ldap_roles(&self, user_id: Uuid) -> Result<Vec<Role>> {
        let roles = sqlx::query_as!(
            Role,
            r#"
            SELECT r.id, r.name, r.description, r.ldap_group_dn, r.created_at
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.ldap_group_dn IS NOT NULL
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    pub async fn remove_role_by_name(&self, user_id: Uuid, role_name: &str) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM user_roles
            WHERE user_id = $1
              AND role_id = (SELECT id FROM roles WHERE name = $2)
            "#,
            user_id,
            role_name
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_permission_names(&self, user_id: Uuid) -> Result<Vec<String>> {
        let permissions = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT p.name
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    pub async fn assign_role_by_name(&self, user_id: Uuid, role_name: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO user_roles (user_id, role_id)
            SELECT $1, id
            FROM roles
            WHERE name = $2
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
            user_id,
            role_name
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>> {
        let role = sqlx::query_as!(
            Role,
            r#"
            SELECT id, name, description, ldap_group_dn, created_at
            FROM roles
            WHERE name = $1
            "#,
            name
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(role)
    }

    pub async fn find_role_by_ldap_group_dn(&self, ldap_group_dn: &str) -> Result<Option<Role>> {
        let role = sqlx::query_as!(
            Role,
            r#"
            SELECT id, name, description, ldap_group_dn, created_at
            FROM roles
            WHERE ldap_group_dn = $1
            "#,
            ldap_group_dn
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(role)
    }

    pub async fn create_local_admin_if_not_exists(&self, username: &str) -> Result<User> {
        let mut tx = self.pool.begin().await?;

        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(user) = existing_user {
            if user.is_local_admin {
                tx.commit().await?;
                return Ok(user);
            }
        }

        let admin_user = User::new(username.to_string())
            .as_local_admin()
            .with_display_name("Local Administrator".to_string());

        let created_user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (username) DO UPDATE
            SET is_local_admin = true, updated_at = NOW()
            RETURNING id, ldap_dn, username, display_name, email, is_local_admin, is_active, created_at, updated_at
            "#,
            admin_user.id,
            admin_user.ldap_dn,
            admin_user.username,
            admin_user.display_name,
            admin_user.email,
            admin_user.is_local_admin,
            admin_user.is_active,
            admin_user.created_at,
            admin_user.updated_at
        )
        .fetch_one(&mut *tx)
        .await?;

        self.assign_role_by_name(created_user.id, &RoleKey::Admin.to_string())
            .await?;

        tx.commit().await?;

        Ok(created_user)
    }
}
