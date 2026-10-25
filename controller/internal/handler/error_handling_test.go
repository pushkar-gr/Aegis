package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func errorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not a JSON error: %v (body: %s)", err, w.Body.String())
	}
	return resp.Error
}

func TestUpdatePasswordWeakPasswordReportsReason(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashed, _ := utils.HashPassword("OldPass123!")
	if _, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "weakpwuser", hashed); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	h := NewAuthHandler(service.NewAuthService(userRepo, service.AuthConfig{JWTKey: []byte("k"), TokenLifetime: time.Hour}))

	r := gin.New()
	r.POST("/api/auth/password", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "weakpwuser")
	}, h.UpdatePassword)

	body, _ := json.Marshal(map[string]string{"old_password": "OldPass123!", "new_password": "weak"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if msg := errorBody(t, w); !strings.HasPrefix(msg, "Password too weak: ") {
		t.Errorf("Expected policy reason in message, got %q", msg)
	}
}

func TestGetCurrentUserDeletedUser(t *testing.T) {
	h, cleanup := newAuthTestRouter(t)
	defer cleanup()

	r := gin.New()
	r.GET("/api/auth/me", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "ghost")
	}, h.GetCurrentUser)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for a user that no longer exists, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshTokenDisabledAccount(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashed, _ := utils.HashPassword("TestPass123!")
	res, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 0)", "disabledrefresh", hashed)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := res.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	token, _ := utils.GenerateSecureToken(32)
	if err := userRepo.CreateRefreshToken(token, int(userID), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	h := NewAuthHandler(service.NewAuthService(userRepo, service.AuthConfig{JWTKey: []byte("k"), TokenLifetime: time.Hour}))
	r := gin.New()
	r.POST("/api/auth/refresh", h.RefreshToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: token})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for disabled account, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRequireRoleUserNoLongerExists(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)

	r := gin.New()
	r.GET("/admin", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "ghost")
	}, middleware.RequireRole(userRepo, "admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for unknown user, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCreateServiceErrorStatuses(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, err := createServiceRepo(t, db)
	if err != nil {
		t.Fatalf("Failed to create service repo: %v", err)
	}
	h := NewServiceHandler(service.NewServiceService(svcRepo, time.Second), userRepo)

	r := gin.New()
	r.POST("/api/services", h.Create)

	post := func(svc models.Service) *httptest.ResponseRecorder {
		body, _ := json.Marshal(svc)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	if w := post(models.Service{Name: "dup-svc", Hostname: "127.0.0.1:9000"}); w.Code != http.StatusCreated {
		t.Fatalf("first create: expected %d, got %d. Body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	tests := []struct {
		name           string
		svc            models.Service
		expectedStatus int
	}{
		{"Duplicate name", models.Service{Name: "dup-svc", Hostname: "127.0.0.1:9001"}, http.StatusConflict},
		{"Missing name", models.Service{Hostname: "127.0.0.1:9002"}, http.StatusBadRequest},
		{"Invalid port", models.Service{Name: "bad-port", Hostname: "127.0.0.1:notaport"}, http.StatusBadRequest},
		{"Missing port", models.Service{Name: "no-port", Hostname: "127.0.0.1"}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := post(tt.svc)
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestUpdateServiceDuplicateName(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	for _, name := range []string{"svc-one", "svc-two"} {
		if _, err := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", name, "127.0.0.1:8080", 0x7F000001, 8080); err != nil {
			t.Fatalf("Failed to create service %s: %v", name, err)
		}
	}
	var secondID int
	if err := db.QueryRow("SELECT id FROM services WHERE name = 'svc-two'").Scan(&secondID); err != nil {
		t.Fatalf("Failed to look up service: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	h := NewServiceHandler(service.NewServiceService(svcRepo, time.Second), userRepo)

	r := gin.New()
	r.PUT("/api/services/:id", h.Update)

	body, _ := json.Marshal(models.Service{Name: "svc-one", Hostname: "127.0.0.1:8080"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/services/%d", secondID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate name, got %d. Body: %s", http.StatusConflict, w.Code, w.Body.String())
	}
}

func TestGetOrCreateOIDCUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashed, _ := utils.HashPassword("TestPass123!")
	if _, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "taken@example.com", hashed); err != nil {
		t.Fatalf("Failed to create local user: %v", err)
	}

	userRepo, roleRepo := createReposFromDB(t, db)
	h := NewOIDCHandler(nil, nil, userRepo, roleRepo)

	t.Run("New identity creates a user", func(t *testing.T) {
		user, err := h.getOrCreateOIDCUser(&oidcUserInfo{Subject: "1001", Email: "new@example.com", EmailVerified: true}, "github", "user")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if user.Username != "new@example.com" {
			t.Errorf("Expected username new@example.com, got %q", user.Username)
		}
	})

	t.Run("Same identity returns the existing user", func(t *testing.T) {
		user, err := h.getOrCreateOIDCUser(&oidcUserInfo{Subject: "1001", Email: "new@example.com", EmailVerified: true}, "github", "user")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if user.Username != "new@example.com" {
			t.Errorf("Expected existing user, got %q", user.Username)
		}
	})

	t.Run("Username owned by another login method is a collision", func(t *testing.T) {
		_, err := h.getOrCreateOIDCUser(&oidcUserInfo{Subject: "2002", Email: "taken@example.com", EmailVerified: true}, "github", "user")
		if !errors.Is(err, errAccountCollision) {
			t.Errorf("Expected errAccountCollision, got %v", err)
		}
	})
}

func TestLoginSSOUserWithoutPassword(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`INSERT INTO users (username, password, role_id, provider, provider_id) VALUES (?, NULL, 2, 'github', '99')`, "ssouser@example.com"); err != nil {
		t.Fatalf("Failed to create SSO user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	h := NewAuthHandler(service.NewAuthService(userRepo, service.AuthConfig{JWTKey: []byte("k"), TokenLifetime: time.Hour}))
	r := gin.New()
	r.POST("/api/auth/login", h.Login)

	body, _ := json.Marshal(map[string]string{"username": "ssouser@example.com", "password": "anything"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}
