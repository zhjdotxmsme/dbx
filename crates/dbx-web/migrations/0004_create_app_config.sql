CREATE TABLE app_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

CREATE INDEX idx_app_config_key ON app_config(key);
