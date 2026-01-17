package database

import (
	"Aegis/controller/internal/models"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates a temporary test database
func setupTestDB(t *testing.T) func() {
	// Create a temporary directory for testing
	tempDir := filepath.Join(os.TempDir(), "aegis-test-"+t.Name())
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	testDBPath := filepath.Join(tempDir, "test_aegis.db")

	// Open test database
	DB, err = sql.Open("sqlite3", testDBPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Enable WAL mode
	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		t.Logf("Warning: Failed to enable WAL mode: %v", err)
	}

	// Configure connection pooling
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)

	// Enable foreign keys
	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create roles table
	createRolesTable := `
		CREATE TABLE IF NOT EXISTS roles (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" TEXT NOT NULL UNIQUE,
			"description" TEXT
		);`
	if _, err := DB.Exec(createRolesTable); err != nil {
		t.Fatalf("Failed to create roles table: %v", err)
	}

	// Seed roles
	seedRoles := `INSERT OR IGNORE INTO roles (name, description) VALUES 
		('admin', 'Administrator with full access'),
		('user', 'Standard user access');`
	if _, err := DB.Exec(seedRoles); err != nil {
		t.Fatalf("Failed to seed roles: %v", err)
	}

	// Create users table
	createUsersTable := `
		CREATE TABLE IF NOT EXISTS users (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"username" TEXT NOT NULL UNIQUE,
			"password" TEXT NOT NULL,
			"role_id" INTEGER NOT NULL DEFAULT 2,
			FOREIGN KEY(role_id) REFERENCES roles(id)
		);`
	if _, err := DB.Exec(createUsersTable); err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	// Prepare the user creation statement
	createUserStmt, err = DB.Prepare(`
		INSERT INTO users (username, password, role_id) 
		VALUES (?, ?, (SELECT id FROM roles WHERE name = ?));`)
	if err != nil {
		t.Fatalf("Failed to prepare create user statement: %v", err)
	}

	// Return cleanup function
	return func() {
		if createUserStmt != nil {
			_ = createUserStmt.Close()
		}
		if DB != nil {
			_ = DB.Close()
		}
		_ = os.RemoveAll(tempDir)
	}
}

func TestCreateUser(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name        string
		user        models.User
		shouldError bool
	}{
		{
			name: "Create admin user",
			user: models.User{
				Creds: models.Credentials{
					Username: "admin1",
					Password: "hashed_password_1",
				},
				Role: "admin",
			},
			shouldError: false,
		},
		{
			name: "Create regular user",
			user: models.User{
				Creds: models.Credentials{
					Username: "user1",
					Password: "hashed_password_2",
				},
				Role: "user",
			},
			shouldError: false,
		},
		{
			name: "Create user with invalid role",
			user: models.User{
				Creds: models.Credentials{
					Username: "user2",
					Password: "hashed_password_3",
				},
				Role: "invalid_role",
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateUser(tt.user)
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	user := models.User{
		Creds: models.Credentials{
			Username: "testuser",
			Password: "hashed_password",
		},
		Role: "user",
	}

	// Create user first time - should succeed
	err := CreateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Try to create the same user again - should fail
	err = CreateUser(user)
	if err == nil {
		t.Error("Expected error when creating duplicate user, but got none")
	}
}

func TestGetUser(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create a test user
	testUser := models.User{
		Creds: models.Credentials{
			Username: "getuser_test",
			Password: "hashed_password_test",
		},
		Role: "admin",
	}

	err := CreateUser(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test getting the user
	retrievedUser, err := GetUser("getuser_test")
	if err != nil {
		t.Errorf("Failed to get user: %v", err)
	}

	if retrievedUser.Creds.Username != testUser.Creds.Username {
		t.Errorf("Expected username %s, got %s", testUser.Creds.Username, retrievedUser.Creds.Username)
	}

	if retrievedUser.Creds.Password != testUser.Creds.Password {
		t.Errorf("Expected password %s, got %s", testUser.Creds.Password, retrievedUser.Creds.Password)
	}

	if retrievedUser.Role != testUser.Role {
		t.Errorf("Expected role %s, got %s", testUser.Role, retrievedUser.Role)
	}
}

func TestGetUserNotFound(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Try to get a non-existent user
	_, err := GetUser("nonexistent_user")
	if err == nil {
		t.Error("Expected error when getting non-existent user, but got none")
	}
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetRole(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name         string
		user         models.User
		expectedRole string
	}{
		{
			name: "Get admin role",
			user: models.User{
				Creds: models.Credentials{
					Username: "admin_role_test",
					Password: "hashed_password",
				},
				Role: "admin",
			},
			expectedRole: "admin",
		},
		{
			name: "Get user role",
			user: models.User{
				Creds: models.Credentials{
					Username: "user_role_test",
					Password: "hashed_password",
				},
				Role: "user",
			},
			expectedRole: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the user
			err := CreateUser(tt.user)
			if err != nil {
				t.Fatalf("Failed to create user: %v", err)
			}

			// Get the role
			role, err := GetRole(tt.user.Creds.Username)
			if err != nil {
				t.Errorf("Failed to get role: %v", err)
			}

			if role != tt.expectedRole {
				t.Errorf("Expected role %s, got %s", tt.expectedRole, role)
			}
		})
	}
}

func TestGetRoleNotFound(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Try to get role for non-existent user
	_, err := GetRole("nonexistent_user")
	if err == nil {
		t.Error("Expected error when getting role for non-existent user, but got none")
	}
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}
