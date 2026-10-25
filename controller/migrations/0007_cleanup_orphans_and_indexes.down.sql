CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
DROP INDEX IF EXISTS idx_users_role_id;
DROP INDEX IF EXISTS idx_user_active_services_service_id;
DROP INDEX IF EXISTS idx_user_extra_services_service_id;
DROP INDEX IF EXISTS idx_role_services_service_id;
