-- 0007_create_audit_log.sql
-- Audit trail for admin cross-user access.
-- Written from crates/dbx-web/src/audit.rs::log_audit when admin uses ?as_user= or ?all=true.
-- action values: 'view_user_history', 'list_user_saved_sql', 'read_saved_sql_file',
--                'view_ai_conversations', 'read_ai_conversation',
--                'list_all_history', 'list_all_saved_sql', 'list_all_ai_conversations',
--                'unauthorized_as_user_attempt', 'admin_as_user_suspicious'
-- Failed audit writes (PG down) surface as X-Audit-Log-Failed response header on the
-- successful main response — never silent.

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id UUID NOT NULL REFERENCES users(id),
    action VARCHAR(50) NOT NULL,
    target_user_id UUID REFERENCES users(id),
    target_resource_id TEXT,
    metadata_json JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX idx_audit_log_target_user_id ON audit_log(target_user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
