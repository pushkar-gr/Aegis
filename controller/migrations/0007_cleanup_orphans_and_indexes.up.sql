DELETE FROM role_services
WHERE role_id NOT IN (SELECT id FROM roles) OR service_id NOT IN (SELECT id FROM services);
DELETE FROM user_extra_services
WHERE user_id NOT IN (SELECT id FROM users) OR service_id NOT IN (SELECT id FROM services);
DELETE FROM user_active_services
WHERE user_id NOT IN (SELECT id FROM users) OR service_id NOT IN (SELECT id FROM services);
DELETE FROM refresh_tokens
WHERE user_id NOT IN (SELECT id FROM users);

CREATE INDEX IF NOT EXISTS idx_role_services_service_id ON role_services(service_id);
CREATE INDEX IF NOT EXISTS idx_user_extra_services_service_id ON user_extra_services(service_id);
CREATE INDEX IF NOT EXISTS idx_user_active_services_service_id ON user_active_services(service_id);
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);

DROP INDEX IF EXISTS idx_refresh_tokens_token;
