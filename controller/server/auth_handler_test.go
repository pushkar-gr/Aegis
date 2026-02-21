package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var testJWTKey = []byte("test-secret-key-for-testing")

func setupTestServer(t *testing.T) func() {
	tempDir := t.TempDir()

	testDBPath := filepath.Join(tempDir, "test_aegis.db")

	var err error
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
		('user', 'Standard user access'),
		('root', 'Root access');`
	if _, err := database.DB.Exec(seedRoles); err != nil {
		t.Fatalf("Failed to seed roles: %v", err)
	}

	createUsersTable := `
		CREATE TABLE IF NOT EXISTS users (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"username" TEXT NOT NULL UNIQUE,
			"password" TEXT NOT NULL,
			"role_id" INTEGER NOT NULL DEFAULT 2,
			"is_active" INTEGER NOT NULL DEFAULT 1,
			"provider" TEXT NOT NULL DEFAULT 'local',
			FOREIGN KEY(role_id) REFERENCES roles(id)
		);`
	if _, err := database.DB.Exec(createUsersTable); err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

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
	if _, err := database.DB.Exec(createServicesTable); err != nil {
		t.Fatalf("Failed to create services table: %v", err)
	}

	createUserActiveServicesTable := `
		CREATE TABLE IF NOT EXISTS user_active_services (
			"user_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			"updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			"time_left" INTEGER DEFAULT 60,
			PRIMARY KEY(user_id, service_id),
			FOREIGN KEY(user_id) REFERENCES users(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createUserActiveServicesTable); err != nil {
		t.Fatalf("Failed to create user_active_services table: %v", err)
	}

	createRoleServicesTable := `
		CREATE TABLE IF NOT EXISTS role_services (
			"role_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			PRIMARY KEY(role_id, service_id),
			FOREIGN KEY(role_id) REFERENCES roles(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createRoleServicesTable); err != nil {
		t.Fatalf("Failed to create role_services table: %v", err)
	}

	createUserExtraServicesTable := `
		CREATE TABLE IF NOT EXISTS user_extra_services (
			"user_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			PRIMARY KEY(user_id, service_id),
			FOREIGN KEY(user_id) REFERENCES users(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createUserExtraServicesTable); err != nil {
		t.Fatalf("Failed to create user_extra_services table: %v", err)
	}

	// Initialize prepared statements for testing
	// We need to call the database initialization to prepare the statements
	if err := database.InitPreparedStatements(); err != nil {
		t.Fatalf("Failed to initialize prepared statements: %v", err)
	}

	createRefreshTokensTable := `
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"token" TEXT NOT NULL UNIQUE,
			"user_id" INTEGER NOT NULL,
			"expires_at" DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);`
	if _, err := database.DB.Exec(createRefreshTokensTable); err != nil {
		t.Fatalf("Failed to create refresh_tokens table: %v", err)
	}

	jwtKey = testJWTKey

	return func() {
		if database.DB != nil {
			_ = database.DB.Close()
		}
	}
}

func TestLogin(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	password := "TestPass123!"
	hashedPassword, _ := utils.HashPassword(password)

	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"loginuser1", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		payload        models.Credentials
		expectedStatus int
		checkCookie    bool
	}{
		{
			name: "Successful login",
			payload: models.Credentials{
				Username: "loginuser1",
				Password: password,
			},
			expectedStatus: http.StatusOK,
			checkCookie:    true,
		},
		{
			name: "Invalid username",
			payload: models.Credentials{
				Username: "nonexistent",
				Password: password,
			},
			expectedStatus: http.StatusUnauthorized,
			checkCookie:    false,
		},
		{
			name: "Invalid password",
			payload: models.Credentials{
				Username: "loginuser1",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			checkCookie:    false,
		},
		{
			name: "Empty credentials",
			payload: models.Credentials{
				Username: "",
				Password: "",
			},
			expectedStatus: http.StatusUnauthorized,
			checkCookie:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			login(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.checkCookie {
				cookies := w.Result().Cookies()
				found := false
				for _, cookie := range cookies {
					if cookie.Name == "token" && cookie.Value != "" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected authentication cookie, but not found")
				}
			}
		})
	}
}

func TestLoginInactiveUser(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	password := "TestPass123!"
	hashedPassword, _ := utils.HashPassword(password)

	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 0)",
		"inactiveuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create inactive test user: %v", err)
	}

	payload := models.Credentials{
		Username: "inactiveuser",
		Password: password,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	login(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for inactive user, got %d", http.StatusForbidden, w.Code)
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestLogout(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	logout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "token" && cookie.Value == "" {
			found = true
			if cookie.Expires.After(time.Now()) {
				t.Error("Expected cookie to be expired")
			}
			break
		}
	}
	if !found {
		t.Error("Expected token cookie to be cleared")
	}
}

func TestUpdatePassword(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	oldPassword := "OldPass123!"
	newPassword := "NewPass456!"
	hashedOldPassword, _ := utils.HashPassword(oldPassword)

	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"passworduser", hashedOldPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		oldPassword    string
		newPassword    string
		expectedStatus int
	}{
		{
			name:           "Successful password update",
			oldPassword:    oldPassword,
			newPassword:    newPassword,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Wrong old password",
			oldPassword:    "WrongPass123!",
			newPassword:    newPassword,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Weak new password",
			oldPassword:    oldPassword,
			newPassword:    "weak",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{
				"old_password": tt.oldPassword,
				"new_password": tt.newPassword,
			}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			ctx := req.Context()
			ctx = contextWithUser(ctx, "passworduser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			updatePassword(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetCurrentUser(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"currentuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test with valid user context
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	ctx := contextWithUser(req.Context(), "currentuser")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	getCurrentUser(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		RoleId   int    `json:"role_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if result.Username != "currentuser" {
		t.Errorf("Expected username 'currentuser', got '%s'", result.Username)
	}
	if result.Role == "" {
		t.Error("Expected non-empty role")
	}
}

func TestGetCurrentUserUnauthorized(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	// No user context set
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()

	getCurrentUser(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshToken(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"refreshuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	// Create a valid refresh token
	token, err := utils.GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	expiry := time.Now().Add(7 * 24 * time.Hour)
	if err := database.CreateRefreshToken(token, int(userID), expiry); err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	// Test refresh with valid token
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: token})
	w := httptest.NewRecorder()

	refreshToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify new token cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "token" && cookie.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected new token cookie to be set")
	}
}

func TestRefreshTokenMissing(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	w := httptest.NewRecorder()

	refreshToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for missing refresh token, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshTokenInvalid(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid-token-xyz"})
	w := httptest.NewRecorder()

	refreshToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for invalid refresh token, got %d", http.StatusUnauthorized, w.Code)
	}
}
