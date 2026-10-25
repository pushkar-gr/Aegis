CREATE TABLE users_old (
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

INSERT INTO users_old (id, username, password, role_id, is_active, provider, provider_id, email)
SELECT id, username, password, role_id, is_active, provider, provider_id, email FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;

CREATE INDEX idx_users_provider_id ON users(provider, provider_id);
CREATE INDEX idx_users_email ON users(email);
