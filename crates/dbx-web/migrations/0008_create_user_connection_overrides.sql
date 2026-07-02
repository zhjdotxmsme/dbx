-- 0008_create_user_connection_overrides.sql
-- Reserved for future fine-grained per-user connection ACL (deny rules).
-- Out of scope for this release. Created as an empty table to lock in the
-- migration number sequence so future work doesn't collide.

CREATE TABLE user_connection_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    -- 'deny' takes precedence over role grant; 'allow' only matters when no role grants it.
    -- This table is not consulted by current code (PR 4 design).
    rule VARCHAR(10) NOT NULL CHECK (rule IN ('allow', 'deny')),
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, connection_id)
);
