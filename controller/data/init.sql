-- Enable Write-Ahead logging for concurrency
PRAGMA journal_mode=WAL;

-- Enforce foreign key constraints
PRAGMA foreign_keys = ON;

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- Services table
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip INTEGER NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

-- Role services (Base permissions for a role)
CREATE TABLE IF NOT EXISTS role_services (
    role_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (role_id, service_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- User extra services (Specific extra permissions for a user)
CREATE TABLE IF NOT EXISTS user_extra_services (
    user_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- User active services (Services the user has currently "Selected")
CREATE TABLE IF NOT EXISTS user_active_services (
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    time_left INTEGER DEFAULT 60,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- Seed roles
INSERT OR IGNORE INTO roles (name, description) VALUES 
('root', 'Super Administrator with full access'),
('admin', 'Administrator with management access'),
('user', 'Standard user');

-- Seed root user
-- username: root, password root
INSERT INTO users (username, password, role_id, is_active)
SELECT 'root', '$2a$12$ZJtnuD8QGgPA4298uOuDF./HHup/v2oDUFJuJ19IIr52OnJ4DOaU6', id, 1
FROM roles 
WHERE name = 'root' 
AND NOT EXISTS (SELECT 1 FROM users WHERE username = 'root');
