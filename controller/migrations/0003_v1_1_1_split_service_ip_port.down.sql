CREATE TABLE services_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_port TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    hostname TEXT NOT NULL DEFAULT 'static-placeholder-hostname'
);

INSERT INTO services_old (id, name, ip_port, description, created_at, hostname)
SELECT id, name,
       ((ip >> 24) & 255) || '.' || ((ip >> 16) & 255) || '.' || ((ip >> 8) & 255) || '.' || (ip & 255) || ':' || port,
       description, created_at, hostname
FROM services;

DROP TABLE services;
ALTER TABLE services_old RENAME TO services;
