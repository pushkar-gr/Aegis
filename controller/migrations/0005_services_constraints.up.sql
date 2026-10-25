UPDATE services
SET name = name || ' (' || id || ')'
WHERE id NOT IN (SELECT MIN(id) FROM services GROUP BY name);

UPDATE services
SET hostname = ((ip >> 24) & 255) || '.' || ((ip >> 16) & 255) || '.' || ((ip >> 8) & 255) || '.' || (ip & 255) || ':' || port
WHERE hostname = 'static-placeholder-hostname';

CREATE TABLE services_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    ip INTEGER NOT NULL CHECK (ip BETWEEN 0 AND 4294967295),
    port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO services_new (id, name, hostname, ip, port, description, created_at)
SELECT id, name, hostname, ip, port, description, created_at FROM services;

DROP TABLE services;
ALTER TABLE services_new RENAME TO services;
