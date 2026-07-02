-- 0006_create_role_connections.sql
-- Role-based connection ACL
-- Existing data: 'everyone' role is created and is the default for all connections during upgrade.
-- Admin assigns specific connections to specific roles via /api/role-connections/grant.

CREATE TABLE role_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    UNIQUE (role_id, connection_id)
);

CREATE INDEX idx_role_connections_role_id ON role_connections(role_id);
CREATE INDEX idx_role_connections_connection_id ON role_connections(connection_id);

-- 'everyone' role: default for all connections on existing deployments.
-- Application-level post-migration (run_post_migration in main.rs) grants every
-- existing SQLite connection to this role so non-admin users keep their access.
INSERT INTO roles (name, description)
VALUES ('everyone', 'Default role auto-granted to existing connections during upgrade')
ON CONFLICT (name) DO NOTHING;
