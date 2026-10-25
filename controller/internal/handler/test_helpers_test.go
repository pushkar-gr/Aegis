package handler

import (
	"Aegis/controller/internal/repository"
	"database/sql"
	"testing"
	"time"
)

// setupTestDB creates an isolated SQLite database using the real migrations.
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	db, err := repository.InitDB(t.TempDir(), 1, 1, time.Hour)
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	if _, err := db.Exec(`UPDATE roles SET id = id + 100`); err != nil {
		t.Fatalf("Failed to renumber roles: %v", err)
	}
	if _, err := db.Exec(`UPDATE roles SET id = CASE name WHEN 'admin' THEN 1 WHEN 'user' THEN 2 WHEN 'root' THEN 3 END`); err != nil {
		t.Fatalf("Failed to renumber roles: %v", err)
	}

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
