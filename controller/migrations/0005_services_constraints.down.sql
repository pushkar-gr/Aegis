CREATE TABLE services_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip INTEGER NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO services_old (id, name, hostname, ip, port, description, created_at)
SELECT id, name, hostname, ip, port, description, created_at FROM services;

DROP TABLE services;
ALTER TABLE services_old RENAME TO services;
