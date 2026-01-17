-- Enable Write-Ahead Logging for concurrency
PRAGMA journal_mode=WAL;

-- Enforce Foreign Key constraints
PRAGMA foreign_keys = ON;

-- 1. Roles Table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- 2. Services Table
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_port TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 3. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

-- 4. Role Services (Base permissions for a role)
CREATE TABLE IF NOT EXISTS role_services (
    role_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (role_id, service_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- 5. User Extra Services (Specific extra permissions for a user)
CREATE TABLE IF NOT EXISTS user_extra_services (
    user_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- 6. User Active Services (Services the user has currently "Selected")
CREATE TABLE IF NOT EXISTS user_active_services (
    user_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- --- SEED DATA ---

-- Seed Roles
INSERT OR IGNORE INTO roles (name, description) VALUES 
('root', 'Super Administrator with full access'),
('admin', 'Administrator with management access'),
('user', 'Standard user');

-- Seed Root User
-- Note: The password string below is a PLACEHOLDER. 
INSERT INTO users (username, password, role_id, is_active)
SELECT 'root', '$2a$10$REPLACE_WITH_VALID_BCRYPT_HASH_FOR_ROOT', id, 1
FROM roles 
WHERE name = 'root' 
AND NOT EXISTS (SELECT 1 FROM users WHERE username = 'root');
