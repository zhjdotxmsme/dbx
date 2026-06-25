INSERT INTO roles (id, name, description) VALUES
    (uuid_generate_v4(), 'viewer', 'Can view connections and execute read-only queries'),
    (uuid_generate_v4(), 'editor', 'Can manage connections and execute queries'),
    (uuid_generate_v4(), 'admin', 'Full administrative access');

INSERT INTO permissions (id, name, description) VALUES
    (uuid_generate_v4(), 'connection:read', 'View database connections'),
    (uuid_generate_v4(), 'connection:write', 'Create and edit connections'),
    (uuid_generate_v4(), 'connection:delete', 'Delete connections'),
    (uuid_generate_v4(), 'query:execute', 'Execute SQL queries'),
    (uuid_generate_v4(), 'query:history:read', 'View query history'),
    (uuid_generate_v4(), 'saved_sql:read', 'View saved SQL files'),
    (uuid_generate_v4(), 'saved_sql:write', 'Create and edit saved SQL'),
    (uuid_generate_v4(), 'ai:use', 'Use AI features'),
    (uuid_generate_v4(), 'settings:read', 'Read application settings'),
    (uuid_generate_v4(), 'settings:write', 'Modify application settings'),
    (uuid_generate_v4(), 'user:manage', 'Manage users and roles'),
    (uuid_generate_v4(), 'admin', 'All permissions');

DO $$
DECLARE
    viewer_id UUID;
    editor_id UUID;
    admin_id UUID;
BEGIN
    SELECT id INTO viewer_id FROM roles WHERE name = 'viewer';
    SELECT id INTO editor_id FROM roles WHERE name = 'editor';
    SELECT id INTO admin_id FROM roles WHERE name = 'admin';

    INSERT INTO role_permissions (role_id, permission_id)
    SELECT viewer_id, id FROM permissions WHERE name IN ('connection:read', 'query:history:read', 'saved_sql:read', 'ai:use');

    INSERT INTO role_permissions (role_id, permission_id)
    SELECT editor_id, id FROM permissions WHERE name IN ('connection:read', 'connection:write', 'query:execute', 'query:history:read', 'saved_sql:read', 'saved_sql:write', 'ai:use');

    INSERT INTO role_permissions (role_id, permission_id)
    SELECT admin_id, id FROM permissions;
END $$;
