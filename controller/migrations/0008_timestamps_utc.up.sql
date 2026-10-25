UPDATE refresh_tokens
SET expires_at = strftime('%Y-%m-%d %H:%M:%f', expires_at)
WHERE expires_at GLOB '*[+-][0-9][0-9]:[0-9][0-9]';

UPDATE refresh_tokens
SET created_at = strftime('%Y-%m-%d %H:%M:%f', created_at)
WHERE created_at GLOB '*[+-][0-9][0-9]:[0-9][0-9]';

UPDATE user_active_services
SET updated_at = strftime('%Y-%m-%d %H:%M:%f', updated_at)
WHERE updated_at GLOB '*[+-][0-9][0-9]:[0-9][0-9]';
