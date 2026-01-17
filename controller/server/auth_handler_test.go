package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates a temporary test database for handler tests
func setupTestDB(t *testing.T) func() {
	tempDir := filepath.Join(os.TempDir(), "aegis-handler-test-"+t.Name())
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	testDBPath := filepath.Join(tempDir, "test_aegis.db")
	database.DB, err = sql.Open("sqlite3", testDBPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	if _, err := database.DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		t.Logf("Warning: Failed to enable WAL mode: %v", err)
	}

	database.DB.SetMaxOpenConns(1)
	database.DB.SetMaxIdleConns(1)

	if _, err := database.DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	createRolesTable := `
		CREATE TABLE IF NOT EXISTS roles (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" TEXT NOT NULL UNIQUE,
			"description" TEXT
		);`
	if _, err := database.DB.Exec(createRolesTable); err != nil {
		t.Fatalf("Failed to create roles table: %v", err)
	}

	seedRoles := `INSERT OR IGNORE INTO roles (name, description) VALUES 
		('admin', 'Administrator with full access'),
		('user', 'Standard user access');`
	if _, err := database.DB.Exec(seedRoles); err != nil {
		t.Fatalf("Failed to seed roles: %v", err)
	}

	createUsersTable := `
		CREATE TABLE IF NOT EXISTS users (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"username" TEXT NOT NULL UNIQUE,
			"password" TEXT NOT NULL,
			"role_id" INTEGER NOT NULL DEFAULT 2,
			FOREIGN KEY(role_id) REFERENCES roles(id)
		);`
	if _, err := database.DB.Exec(createUsersTable); err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	// Prepare the createUserStmt for testing
	if err := database.SetupTestStmt(); err != nil {
		t.Fatalf("Failed to setup test statement: %v", err)
	}

	return func() {
		if database.DB != nil {
			_ = database.DB.Close()
		}
		_ = os.RemoveAll(tempDir)
	}
}

func TestLogin(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set JWT key for testing (note: this modifies a global variable)
	// Save original key and restore after test
	originalKey := jwtKey
	jwtKey = []byte("test-jwt-secret")
	defer func() {
		jwtKey = originalKey
	}()

	// Create a test user with hashed password
	password := "TestPassword123!"
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	_, err = database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"testuser", hashedPassword, "user",
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		credentials    models.Credentials
		expectedStatus int
		checkCookie    bool
	}{
		{
			name:   "Successful login",
			method: http.MethodPost,
			credentials: models.Credentials{
				Username: "testuser",
				Password: password,
			},
			expectedStatus: http.StatusOK,
			checkCookie:    true,
		},
		{
			name:   "Wrong password",
			method: http.MethodPost,
			credentials: models.Credentials{
				Username: "testuser",
				Password: "WrongPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			checkCookie:    false,
		},
		{
			name:   "Non-existent user",
			method: http.MethodPost,
			credentials: models.Credentials{
				Username: "nonexistent",
				Password: password,
			},
			expectedStatus: http.StatusUnauthorized,
			checkCookie:    false,
		},
		{
			name:   "Wrong method (GET)",
			method: http.MethodGet,
			credentials: models.Credentials{
				Username: "testuser",
				Password: password,
			},
			expectedStatus: http.StatusMethodNotAllowed,
			checkCookie:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.credentials)
			req := httptest.NewRequest(tt.method, "/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			Login(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.checkCookie {
				cookies := rr.Result().Cookies()
				found := false
				for _, cookie := range cookies {
					if cookie.Name == "token" {
						found = true
						if cookie.Value == "" {
							t.Error("Expected non-empty token cookie")
						}
						if !cookie.HttpOnly {
							t.Error("Expected HttpOnly flag on cookie")
						}
						if !cookie.Secure {
							t.Error("Expected Secure flag on cookie")
						}
						break
					}
				}
				if !found {
					t.Error("Expected token cookie to be set")
				}
			}
		})
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	jwtKey = []byte("test-jwt-secret")

	// Test with invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Successful logout",
			method:         http.MethodPost,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Wrong method (GET)",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/logout", nil)
			rr := httptest.NewRecorder()

			Logout(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				// Check that the cookie is cleared
				cookies := rr.Result().Cookies()
				found := false
				for _, cookie := range cookies {
					if cookie.Name == "token" {
						found = true
						if cookie.Value != "" {
							t.Error("Expected empty token value on logout")
						}
						if !cookie.Expires.Before(time.Now()) {
							t.Error("Expected expired cookie on logout")
						}
						break
					}
				}
				if !found {
					t.Error("Expected token cookie to be set (for clearing)")
				}
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create an admin user for authorization
	adminPassword, _ := utils.HashPassword("AdminPass123!")
	_, err := database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"adminuser", adminPassword, "admin",
	)
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Create a regular user for testing permission denial
	userPassword, _ := utils.HashPassword("UserPass123!")
	_, err = database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"regularuser", userPassword, "user",
	)
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		contextUser    string
		newUser        models.User
		expectedStatus int
	}{
		{
			name:        "Admin creates user successfully",
			method:      http.MethodPost,
			contextUser: "adminuser",
			newUser: models.User{
				Creds: models.Credentials{
					Username: "newuser1",
					Password: "NewPass123!",
				},
				Role: "user",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:        "Admin creates admin successfully",
			method:      http.MethodPost,
			contextUser: "adminuser",
			newUser: models.User{
				Creds: models.Credentials{
					Username: "newadmin1",
					Password: "NewPass123!",
				},
				Role: "admin",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:        "Non-admin tries to create user",
			method:      http.MethodPost,
			contextUser: "regularuser",
			newUser: models.User{
				Creds: models.Credentials{
					Username: "newuser2",
					Password: "NewPass123!",
				},
				Role: "user",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:        "Invalid username format",
			method:      http.MethodPost,
			contextUser: "adminuser",
			newUser: models.User{
				Creds: models.Credentials{
					Username: "usr", // Too short
					Password: "NewPass123!",
				},
				Role: "user",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Weak password",
			method:      http.MethodPost,
			contextUser: "adminuser",
			newUser: models.User{
				Creds: models.Credentials{
					Username: "newuser3",
					Password: "weak", // Doesn't meet complexity requirements
				},
				Role: "user",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Wrong method (GET)",
			method:         http.MethodGet,
			contextUser:    "adminuser",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodPost {
				body, _ := json.Marshal(tt.newUser)
				req = httptest.NewRequest(tt.method, "/createuser", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/createuser", nil)
			}

			// Add username to context
			ctx := context.WithValue(req.Context(), UserKey, tt.contextUser)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			CreateUser(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestCreateUserInvalidJSON(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create an admin user
	adminPassword, _ := utils.HashPassword("AdminPass123!")
	_, err := database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"adminuser", adminPassword, "admin",
	)
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/createuser", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), UserKey, "adminuser")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	CreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestCreateUserDuplicateUsername(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create an admin user
	adminPassword, _ := utils.HashPassword("AdminPass123!")
	_, err := database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"adminuser", adminPassword, "admin",
	)
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Create a user that already exists
	existingPassword, _ := utils.HashPassword("ExistingPass123!")
	_, err = database.DB.Exec(
		"INSERT INTO users (username, password, role_id) VALUES (?, ?, (SELECT id FROM roles WHERE name = ?))",
		"existinguser", existingPassword, "user",
	)
	if err != nil {
		t.Fatalf("Failed to create existing user: %v", err)
	}

	// Try to create a user with the same username
	newUser := models.User{
		Creds: models.Credentials{
			Username: "existinguser",
			Password: "NewPass123!",
		},
		Role: "user",
	}

	body, _ := json.Marshal(newUser)
	req := httptest.NewRequest(http.MethodPost, "/createuser", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), UserKey, "adminuser")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	CreateUser(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d for duplicate username, got %d", http.StatusInternalServerError, rr.Code)
	}
}
