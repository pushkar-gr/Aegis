package handler

import (
	"Aegis/controller/internal/repository"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

const testSchema = `
CREATE TABLE IF NOT EXISTS roles (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	description TEXT
);
CREATE TABLE IF NOT EXISTS users (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password TEXT,
	role_id INTEGER NOT NULL DEFAULT 2,
	is_active INTEGER NOT NULL DEFAULT 1,
	provider TEXT DEFAULT 'local',
	provider_id TEXT,
	email TEXT,
	FOREIGN KEY(role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS services (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	hostname TEXT NOT NULL,
	ip INTEGER NOT NULL,
	port INTEGER NOT NULL,
	description TEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_active_services (
	user_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	time_left INTEGER DEFAULT 60,
	PRIMARY KEY(user_id, service_id),
	FOREIGN KEY(user_id) REFERENCES users(id),
	FOREIGN KEY(service_id) REFERENCES services(id)
);
CREATE TABLE IF NOT EXISTS role_services (
	role_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	PRIMARY KEY(role_id, service_id),
	FOREIGN KEY(role_id) REFERENCES roles(id),
	FOREIGN KEY(service_id) REFERENCES services(id)
);
CREATE TABLE IF NOT EXISTS user_extra_services (
	user_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	PRIMARY KEY(user_id, service_id),
	FOREIGN KEY(user_id) REFERENCES users(id),
	FOREIGN KEY(service_id) REFERENCES services(id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	token TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	expires_at DATETIME NOT NULL,
	FOREIGN KEY(user_id) REFERENCES users(id)
);
`

// setupTestDB creates an isolated SQLite test database and returns the db and cleanup function.
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test_aegis.db")

	db, err := sql.Open("sqlite3", testDBPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	if _, err := db.Exec(testSchema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	seedRoles := `INSERT OR IGNORE INTO roles (name, description) VALUES
		('admin', 'Administrator with full access'),
		('user', 'Standard user access'),
		('root', 'Root access');`
	if _, err := db.Exec(seedRoles); err != nil {
		t.Fatalf("Failed to seed roles: %v", err)
	}

	// Set the global DB for watcher/grpc compatibility
	repository.DB = db

	return db, func() { _ = db.Close() }
}

// setupTestRepos creates all repositories from a test database.
func setupTestRepos(t *testing.T) (repository.UserRepository, repository.ServiceRepository, repository.RoleRepository, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	userRepo, roleRepo := createReposFromDB(t, db)
	svcRepo, err := repository.NewServiceRepository(db)
	if err != nil {
		t.Fatalf("Failed to create service repo: %v", err)
	}
	return userRepo, svcRepo, roleRepo, cleanup
}

// createReposFromDB creates user and role repos from an existing db.
func createReposFromDB(t *testing.T, db *sql.DB) (repository.UserRepository, repository.RoleRepository) {
	t.Helper()
	userRepo, err := repository.NewUserRepository(db)
	if err != nil {
		t.Fatalf("Failed to create user repo: %v", err)
	}
	roleRepo, err := repository.NewRoleRepository(db)
	if err != nil {
		t.Fatalf("Failed to create role repo: %v", err)
	}
	return userRepo, roleRepo
}

// createServiceRepo creates a ServiceRepository from an existing db.
func createServiceRepo(t *testing.T, db *sql.DB) (repository.ServiceRepository, error) {
	t.Helper()
	return repository.NewServiceRepository(db)
}
