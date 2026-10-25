DROP TABLE refresh_tokens;

CREATE TABLE users_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

INSERT INTO users_old (id, username, password, role_id, is_active)
SELECT id, username, COALESCE(password, ''), role_id, is_active FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;
