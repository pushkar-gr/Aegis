INSERT OR IGNORE INTO roles (name, description) VALUES
    ('root', 'Super Administrator with full access'),
    ('admin', 'Administrator with management access'),
    ('user', 'Standard user');

CREATE TABLE users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT,
    role_id INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    provider TEXT NOT NULL DEFAULT 'local',
    provider_id TEXT,
    email TEXT,
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE RESTRICT,
    CHECK (provider <> 'local' OR password IS NOT NULL)
);

INSERT INTO users_new (id, username, password, role_id, is_active, provider, provider_id, email)
SELECT
    id,
    username,
    password,
    CASE WHEN EXISTS (SELECT 1 FROM roles r WHERE r.id = users.role_id)
         THEN role_id
         ELSE (SELECT id FROM roles WHERE name = 'user') END,
    COALESCE(is_active, 1),
    COALESCE(provider, 'local'),
    provider_id,
    email
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_users_provider_identity ON users(provider, provider_id) WHERE provider_id IS NOT NULL;
