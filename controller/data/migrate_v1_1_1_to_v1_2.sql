-- Add OIDC fields to users table
ALTER TABLE users ADD COLUMN provider TEXT DEFAULT 'local';
ALTER TABLE users ADD COLUMN provider_id TEXT;
ALTER TABLE users ADD COLUMN email TEXT;

-- Make password nullable for OIDC users
CREATE TABLE users_new (
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

-- Copy data from old table to new table
INSERT INTO users_new (id, username, password, role_id, is_active, provider, provider_id, email)
SELECT id, username, password, role_id, is_active, 
       COALESCE(provider, 'local') as provider, 
       provider_id, 
       email
FROM users;

-- Drop the old table
DROP TABLE users;

-- Rename the new table to the original name
ALTER TABLE users_new RENAME TO users;

-- Create index on provider_id for faster OIDC lookups
CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider, provider_id);

-- Create index on email for faster email-based lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
