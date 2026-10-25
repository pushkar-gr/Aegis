CREATE TABLE users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    provider TEXT DEFAULT 'local',
    provider_id TEXT,
    email TEXT,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

INSERT INTO users_new (id, username, password, role_id, is_active)
SELECT id, username, password, role_id, is_active FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE INDEX idx_users_provider_id ON users(provider, provider_id);
CREATE INDEX idx_users_email ON users(email);

CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
