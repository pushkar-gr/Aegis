-- Disable foreign keys for the operation
PRAGMA foreign_keys=OFF;

BEGIN TRANSACTION;

-- Create the new services table with separate ip and port columns
CREATE TABLE IF NOT EXISTS services_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip INTEGER NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Migrate and convert data
INSERT INTO services_new (id, name, hostname, description, created_at, ip, port)
WITH raw_split AS (
    -- Separate the IP string and the Port string
    SELECT 
        id, name, hostname, description, created_at,
        substr(ip_port, 1, instr(ip_port, ':') - 1) AS ip_str,
        CAST(substr(ip_port, instr(ip_port, ':') + 1) AS INTEGER) AS port_val
    FROM services
    WHERE instr(ip_port, ':') > 0
),
dots AS (
    -- Find the positions of the three dots in the IP string "A.B.C.D"
    SELECT 
        *,
        instr(ip_str, '.') AS d1,
        instr(substr(ip_str, instr(ip_str, '.') + 1), '.') + instr(ip_str, '.') AS d2,
        instr(substr(ip_str, instr(substr(ip_str, instr(ip_str, '.') + 1), '.') + instr(ip_str, '.') + 1), '.') 
            + instr(substr(ip_str, instr(ip_str, '.') + 1), '.') + instr(ip_str, '.') AS d3
    FROM raw_split
),
octets AS (
    -- Extract the four octets as integers
    SELECT 
        *,
        CAST(substr(ip_str, 1, d1 - 1) AS INTEGER) AS o1,
        CAST(substr(ip_str, d1 + 1, d2 - d1 - 1) AS INTEGER) AS o2,
        CAST(substr(ip_str, d2 + 1, d3 - d2 - 1) AS INTEGER) AS o3,
        CAST(substr(ip_str, d3 + 1) AS INTEGER) AS o4
    FROM dots
)
SELECT 
    id, 
    name, 
    hostname, 
    description, 
    created_at,
    (o1 << 24) | (o2 << 16) | (o3 << 8) | o4 AS ip, -- Combine octets into 32-bit integer
    port_val AS port
FROM octets;

-- Swap the tables
DROP TABLE services;
ALTER TABLE services_new RENAME TO services;

COMMIT;

-- Re-enable foreign keys
PRAGMA foreign_keys=ON;
