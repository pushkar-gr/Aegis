package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newAuthTestRouter(t *testing.T) (*AuthHandler, func()) {
	t.Helper()
	userRepo, _, _, cleanup := setupTestRepos(t)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	return NewAuthHandler(authSvc), cleanup
}

func TestLogin(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	password := "TestPass123!"
	hashedPassword, _ := utils.HashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "loginuser1", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.POST("/api/auth/login", h.Login)

	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
		checkCookie    bool
	}{
		{"Successful login", "loginuser1", password, http.StatusOK, true},
		{"Invalid username", "nonexistent", password, http.StatusUnauthorized, false},
		{"Invalid password", "loginuser1", "wrongpassword", http.StatusUnauthorized, false},
		{"Empty credentials", "", "", http.StatusUnauthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"username": tt.username, "password": tt.password})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.checkCookie {
				found := false
				for _, cookie := range w.Result().Cookies() {
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
	db, cleanup := setupTestDB(t)
	defer cleanup()

	password := "TestPass123!"
	hashedPassword, _ := utils.HashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 0)", "inactiveuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create inactive test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.POST("/api/auth/login", h.Login)

	body, _ := json.Marshal(map[string]string{"username": "inactiveuser", "password": password})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for inactive user, got %d", http.StatusForbidden, w.Code)
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.POST("/api/auth/login", h.Login)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestLogout(t *testing.T) {
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.POST("/api/auth/logout", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "testuser")
	}, h.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	found := false
	for _, cookie := range w.Result().Cookies() {
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
	db, cleanup := setupTestDB(t)
	defer cleanup()

	oldPassword := "OldPass123!"
	newPassword := "NewPass456!"
	hashedOldPassword, _ := utils.HashPassword(oldPassword)
	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "passworduser", hashedOldPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.POST("/api/auth/password", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "passworduser")
	}, h.UpdatePassword)

	tests := []struct {
		name           string
		oldPassword    string
		newPassword    string
		expectedStatus int
	}{
		{"Successful password update", oldPassword, newPassword, http.StatusOK},
		{"Wrong old password", "WrongPass123!", newPassword, http.StatusUnauthorized},
		{"Weak new password", oldPassword, "weak", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{"old_password": tt.oldPassword, "new_password": tt.newPassword}
			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetCurrentUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "currentuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.GET("/api/auth/me", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "currentuser")
	}, h.GetCurrentUser)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.ServeHTTP(w, req)

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
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.GET("/api/auth/me", h.GetCurrentUser)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "refreshuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	token, _ := utils.GenerateSecureToken(32)
	expiry := time.Now().Add(7 * 24 * time.Hour)
	if err := userRepo.CreateRefreshToken(token, int(userID), expiry); err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.POST("/api/auth/refresh", h.RefreshToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: token})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}

	found := false
	for _, cookie := range w.Result().Cookies() {
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
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.POST("/api/auth/refresh", h.RefreshToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for missing refresh token, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshTokenInvalid(t *testing.T) {
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.POST("/api/auth/refresh", h.RefreshToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid-token-xyz"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for invalid refresh token, got %d", http.StatusUnauthorized, w.Code)
	}
}
