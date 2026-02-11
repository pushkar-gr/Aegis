package database

import (
	"Aegis/controller/internal/utils"
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

	// Create services table
	createServicesTable := `
CREATE TABLE IF NOT EXISTS services (
"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
"name" TEXT NOT NULL UNIQUE,
"hostname" TEXT NOT NULL,
"ip" INTEGER NOT NULL,
"port" INTEGER NOT NULL,
"description" TEXT,
"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
	if _, err := DB.Exec(createServicesTable); err != nil {
		t.Fatalf("Failed to create services table: %v", err)
	}

	// Create user_active_services table
	createActiveServicesTable := `
CREATE TABLE IF NOT EXISTS user_active_services (
"user_id" INTEGER NOT NULL,
"service_id" INTEGER NOT NULL,
"updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
"time_left" INTEGER DEFAULT 60,
PRIMARY KEY(user_id, service_id),
FOREIGN KEY(user_id) REFERENCES users(id),
FOREIGN KEY(service_id) REFERENCES services(id)
);`
	if _, err := DB.Exec(createActiveServicesTable); err != nil {
		t.Fatalf("Failed to create user_active_services table: %v", err)
	}

	// Create role_services table
	createRoleServicesTable := `
CREATE TABLE IF NOT EXISTS role_services (
"role_id" INTEGER NOT NULL,
"service_id" INTEGER NOT NULL,
PRIMARY KEY(role_id, service_id),
FOREIGN KEY(role_id) REFERENCES roles(id),
FOREIGN KEY(service_id) REFERENCES services(id)
);`
	if _, err := DB.Exec(createRoleServicesTable); err != nil {
		t.Fatalf("Failed to create role_services table: %v", err)
	}

	// Create user_extra_services table
	createUserExtraServicesTable := `
CREATE TABLE IF NOT EXISTS user_extra_services (
"user_id" INTEGER NOT NULL,
"service_id" INTEGER NOT NULL,
PRIMARY KEY(user_id, service_id),
FOREIGN KEY(user_id) REFERENCES users(id),
FOREIGN KEY(service_id) REFERENCES services(id)
);`
	if _, err := DB.Exec(createUserExtraServicesTable); err != nil {
		t.Fatalf("Failed to create user_extra_services table: %v", err)
	}

	// Initialize prepared statements
	if err := InitPreparedStatements(); err != nil {
		t.Fatalf("Failed to prepare statements: %v", err)
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

func TestGetServiceIPPort(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create a test service
	result, err := DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"test_service", "192.168.1.100:8080", 0xC0A80164, 8080, "Test service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	serviceID, _ := result.LastInsertId()

	ip, port, err := GetServiceIPPort(int(serviceID))
	if err != nil {
		t.Errorf("GetServiceIPPort failed: %v", err)
	}

	if ip != 0xC0A80164 || port != 8080 {
		t.Errorf("Expected ip_port '192.168.1.100:8080', got %s:%d", utils.Uint32ToIp(ip), port)
	}
}

func TestInsertAndDeleteActiveService(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create test user and service
	_, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"testuser", "pass")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	_, err = DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"test_service", "192.168.1.100:8080", 0xC0A80164, 8080, "Test service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	// Test insert
	err = InsertActiveService(1, 1, 60)
	if err != nil {
		t.Errorf("InsertActiveService failed: %v", err)
	}

	// Verify insert
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM user_active_services WHERE user_id = 1 AND service_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query active services: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 active service, got %d", count)
	}

	// Test delete
	err = DeleteActiveService(1, 1)
	if err != nil {
		t.Errorf("DeleteActiveService failed: %v", err)
	}

	// Verify delete
	err = DB.QueryRow("SELECT COUNT(*) FROM user_active_services WHERE user_id = 1 AND service_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query active services: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 active services after delete, got %d", count)
	}
}

func TestCheckUserExists(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create test user
	result, err := DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"testuser", "pass")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, _ := result.LastInsertId()

	// Test existing user
	exists, err := CheckUserExists(int(userID))
	if err != nil {
		t.Errorf("CheckUserExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected user to exist")
	}

	// Test non-existing user
	exists, err = CheckUserExists(99999)
	if err != nil {
		t.Errorf("CheckUserExists failed: %v", err)
	}
	if exists {
		t.Error("Expected user to not exist")
	}
}

func TestCheckServiceExists(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create test service
	result, err := DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"test_service", "192.168.1.100:8080", 0xC0A80164, 8080, "Test")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	serviceID, _ := result.LastInsertId()

	// Test existing service
	exists, err := CheckServiceExists(int(serviceID))
	if err != nil {
		t.Errorf("CheckServiceExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected service to exist")
	}

	// Test non-existing service
	exists, err = CheckServiceExists(99999)
	if err != nil {
		t.Errorf("CheckServiceExists failed: %v", err)
	}
	if exists {
		t.Error("Expected service to not exist")
	}
}
