package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) func() {
	tempDir := filepath.Join(os.TempDir(), "aegis-test-"+t.Name())
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	testDBPath := filepath.Join(tempDir, "test_aegis.db")

	DB, err = sql.Open("sqlite3", testDBPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		t.Logf("Warning: Failed to enable WAL mode: %v", err)
	}

	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)

	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	createRolesTable := `
CREATE TABLE IF NOT EXISTS roles (
"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
"name" TEXT NOT NULL UNIQUE,
"description" TEXT
);`
	if _, err := DB.Exec(createRolesTable); err != nil {
		t.Fatalf("Failed to create roles table: %v", err)
	}

	seedRoles := `INSERT OR IGNORE INTO roles (name, description) VALUES 
('admin', 'Administrator with full access'),
('user', 'Standard user access'),
('root', 'Root access');`
	if _, err := DB.Exec(seedRoles); err != nil {
		t.Fatalf("Failed to seed roles: %v", err)
	}

	createUsersTable := `
CREATE TABLE IF NOT EXISTS users (
"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
"username" TEXT NOT NULL UNIQUE,
"password" TEXT NOT NULL,
"role_id" INTEGER NOT NULL DEFAULT 2,
"is_active" INTEGER NOT NULL DEFAULT 1,
FOREIGN KEY(role_id) REFERENCES roles(id)
);`
	if _, err := DB.Exec(createUsersTable); err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	stmtGetUserCredentials, err = DB.Prepare("SELECT password, is_active FROM users WHERE username = ?")
	if err != nil {
		t.Fatalf("Failed to prepare stmtGetUserCredentials: %v", err)
	}

	stmtGetUserIDAndRole, err = DB.Prepare("SELECT id, role_id FROM users WHERE username = ?")
	if err != nil {
		t.Fatalf("Failed to prepare stmtGetUserIDAndRole: %v", err)
	}

	stmtUpdatePassword, err = DB.Prepare("UPDATE users SET password = ? WHERE username = ?")
	if err != nil {
		t.Fatalf("Failed to prepare stmtUpdatePassword: %v", err)
	}

	return func() {
		if stmtGetUserCredentials != nil {
			_ = stmtGetUserCredentials.Close()
		}
		if stmtGetUserIDAndRole != nil {
			_ = stmtGetUserIDAndRole.Close()
		}
		if stmtUpdatePassword != nil {
			_ = stmtUpdatePassword.Close()
		}
		if DB != nil {
			_ = DB.Close()
		}
		_ = os.RemoveAll(tempDir)
	}
}

func TestGetUserCredentials(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	testUsername := "testuser"
	testPassword := "hashed_password_123"

	_, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	passwordHash, isActive, err := GetUserCredentials(testUsername)
	if err != nil {
		t.Errorf("GetUserCredentials failed: %v", err)
	}

	if passwordHash != testPassword {
		t.Errorf("Expected password %s, got %s", testPassword, passwordHash)
	}

	if !isActive {
		t.Error("Expected user to be active")
	}
}

func TestGetUserCredentialsNotFound(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	_, _, err := GetUserCredentials("nonexistent_user")
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetUserIDAndRole(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	testUsername := "testuser2"

	result, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 1, 1)",
		testUsername, "password")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	expectedID, _ := result.LastInsertId()

	id, roleID, err := GetUserIDAndRole(testUsername)
	if err != nil {
		t.Errorf("GetUserIDAndRole failed: %v", err)
	}

	if int64(id) != expectedID {
		t.Errorf("Expected user ID %d, got %d", expectedID, id)
	}

	if roleID != 1 {
		t.Errorf("Expected role ID 1, got %d", roleID)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	testUsername := "testuser3"
	oldPassword := "old_hashed_password"
	newPassword := "new_hashed_password"

	_, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		testUsername, oldPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rowsAffected, err := UpdateUserPassword(testUsername, newPassword)
	if err != nil {
		t.Errorf("UpdateUserPassword failed: %v", err)
	}

	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", rowsAffected)
	}

	var storedPassword string
	err = DB.QueryRow("SELECT password FROM users WHERE username = ?", testUsername).Scan(&storedPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve updated password: %v", err)
	}

	if storedPassword != newPassword {
		t.Errorf("Expected password %s, got %s", newPassword, storedPassword)
	}
}

func TestGetPasswordHash(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	testUsername := "testuser4"
	testPassword := "hashed_password_456"

	_, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	hash, err := GetPasswordHash(testUsername)
	if err != nil {
		t.Errorf("GetPasswordHash failed: %v", err)
	}

	if hash != testPassword {
		t.Errorf("Expected password hash %s, got %s", testPassword, hash)
	}
}

func TestGetPasswordHashNotFound(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	_, err := GetPasswordHash("nonexistent_user")
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}
