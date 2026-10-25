CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_port TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

CREATE TABLE role_services (
    role_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (role_id, service_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE user_extra_services (
    user_id INTEGER,
    service_id INTEGER,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE user_active_services (
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    time_left INTEGER DEFAULT 60,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- The application relies on these roles existing.
INSERT INTO roles (name, description) VALUES
    ('root', 'Super Administrator with full access'),
    ('admin', 'Administrator with management access'),
    ('user', 'Standard user');
