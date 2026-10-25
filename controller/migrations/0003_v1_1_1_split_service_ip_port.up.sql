CREATE TABLE services_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip INTEGER NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO services_new (id, name, hostname, description, created_at, ip, port)
WITH parts AS (
    SELECT
        id, name, description, created_at,
        CASE WHEN hostname = 'static-placeholder-hostname' THEN ip_port ELSE hostname END AS hostname,
        CASE WHEN instr(ip_port, ':') > 0 THEN substr(ip_port, 1, instr(ip_port, ':') - 1) ELSE ip_port END AS ip_str,
        CASE WHEN instr(ip_port, ':') > 0 THEN substr(ip_port, instr(ip_port, ':') + 1) ELSE '' END AS port_str
    FROM services
),
shape AS (
    SELECT *,
        (ip_str <> ''
            AND ip_str NOT GLOB '*[^0-9.]*'
            AND ip_str NOT GLOB '*..*'
            AND ip_str NOT GLOB '.*'
            AND ip_str NOT GLOB '*.'
            AND length(ip_str) - length(replace(ip_str, '.', '')) = 3) AS dotted,
        (port_str <> '' AND port_str NOT GLOB '*[^0-9]*' AND length(port_str) <= 5) AS numeric_port
    FROM parts
),
dot1 AS (
    SELECT *, instr(ip_str, '.') AS d1 FROM shape
),
dot2 AS (
    SELECT *, d1 + instr(substr(ip_str, d1 + 1), '.') AS d2 FROM dot1
),
dot3 AS (
    SELECT *, d2 + instr(substr(ip_str, d2 + 1), '.') AS d3 FROM dot2
),
octets AS (
    SELECT *,
        CAST(substr(ip_str, 1, d1 - 1) AS INTEGER) AS o1,
        CAST(substr(ip_str, d1 + 1, d2 - d1 - 1) AS INTEGER) AS o2,
        CAST(substr(ip_str, d2 + 1, d3 - d2 - 1) AS INTEGER) AS o3,
        CAST(substr(ip_str, d3 + 1) AS INTEGER) AS o4
    FROM dot3
)
SELECT
    id, name, hostname, description, created_at,
    CASE WHEN dotted AND o1 <= 255 AND o2 <= 255 AND o3 <= 255 AND o4 <= 255
         THEN (o1 << 24) | (o2 << 16) | (o3 << 8) | o4
         ELSE 0 END,
    CASE WHEN numeric_port AND CAST(port_str AS INTEGER) <= 65535
         THEN CAST(port_str AS INTEGER)
         ELSE 0 END
FROM octets;

DROP TABLE services;
ALTER TABLE services_new RENAME TO services;
