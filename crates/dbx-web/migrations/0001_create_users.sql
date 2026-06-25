CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ldap_dn VARCHAR(500) UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    email VARCHAR(255),
    is_local_admin BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_ldap_dn ON users(ldap_dn);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
