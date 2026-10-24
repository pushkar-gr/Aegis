package handler

import (
	oidcPkg "Aegis/controller/internal/oidc"
	"Aegis/controller/internal/service"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestListOIDCProviders(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, roleRepo := createReposFromDB(t, db)

	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})

	tests := []struct {
		name           string
		setupOIDC      bool
		expectedStatus int
		expectedCount  int
	}{
		{
			name:           "OIDC not enabled",
			setupOIDC:      false,
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "OIDC enabled with providers",
			setupOIDC:      true,
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oidcHandler *OIDCHandler
			if tt.setupOIDC {
				ctx := context.Background()
				manager, err := oidcPkg.NewOIDCManager(
					ctx, "", "",
					"test-github-client", "test-github-secret",
					"http://localhost/callback",
					`{"default_role": "user"}`,
				)
				if err != nil {
					t.Fatalf("Failed to create OIDC manager: %v", err)
				}
				oidcHandler = NewOIDCHandler(manager, authSvc, userRepo, roleRepo)
			} else {
				oidcHandler = NewOIDCHandler(nil, authSvc, userRepo, roleRepo)
			}

			r := gin.New()
			r.GET("/api/auth/oidc/providers", oidcHandler.ListProviders)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/providers", nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.setupOIDC && w.Code == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				providers, ok := response["providers"].([]interface{})
				if !ok {
					t.Fatalf("Expected providers array in response")
				}
				if len(providers) != tt.expectedCount {
					t.Errorf("Expected %d providers, got %d", tt.expectedCount, len(providers))
				}
			}
		})
	}
}

func TestOIDCCallbackMissingState(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, roleRepo := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})

	ctx := context.Background()
	manager, err := oidcPkg.NewOIDCManager(
		ctx, "", "",
		"test-github-client", "test-github-secret",
		"http://localhost/callback",
		`{"default_role": "user"}`,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}
	oidcHandler := NewOIDCHandler(manager, authSvc, userRepo, roleRepo)

	r := gin.New()
	r.GET("/api/auth/oidc/callback", oidcHandler.Callback)

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{"Missing state parameter", "code=test-code", http.StatusBadRequest},
		{"Missing code parameter", "state=test-state", http.StatusBadRequest},
		{"Both parameters missing", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/auth/oidc/callback"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, url, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestUpdatePasswordOIDCUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`INSERT INTO users (username, password, email, provider, provider_id, role_id, is_active) VALUES (?, '', ?, ?, ?, 2, 1)`,
		"oidcuser", "oidcuser@example.com", "google", "google-123"); err != nil {
		t.Fatalf("Failed to create OIDC test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})
	h := NewAuthHandler(authSvc)

	r := gin.New()
	r.POST("/api/auth/password", func(c *gin.Context) {
		c.Set("username", "oidcuser")
	}, h.UpdatePassword)

	body, _ := json.Marshal(map[string]string{
		"old_password": "irrelevant",
		"new_password": "NewPass456!",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for OIDC user password change, got %d. Body: %s",
			http.StatusForbidden, w.Code, w.Body.String())
	}
}

func TestOIDCLogin(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, roleRepo := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})

	ctx := context.Background()
	manager, err := oidcPkg.NewOIDCManager(
		ctx, "", "",
		"test-github-client", "test-github-secret",
		"http://localhost/callback",
		`{"default_role": "user"}`,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}

	tests := []struct {
		name           string
		oidcManager    *oidcPkg.OIDCManager
		queryParam     string
		expectedStatus int
	}{
		{
			name:           "OIDC not enabled",
			oidcManager:    nil,
			queryParam:     "?provider=github",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Missing provider parameter",
			oidcManager:    manager,
			queryParam:     "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid provider name",
			oidcManager:    manager,
			queryParam:     "?provider=nonexistent",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Valid provider redirects",
			oidcManager:    manager,
			queryParam:     "?provider=github",
			expectedStatus: http.StatusTemporaryRedirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewOIDCHandler(tt.oidcManager, authSvc, userRepo, roleRepo)
			r := gin.New()
			r.GET("/api/auth/oidc/login", h.Login)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login"+tt.queryParam, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestOIDCCallbackInvalidState(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, roleRepo := createReposFromDB(t, db)
	authSvc := service.NewAuthService(userRepo, service.AuthConfig{
		JWTKey:        []byte("test-secret-key"),
		TokenLifetime: time.Hour,
	})

	ctx := context.Background()
	manager, err := oidcPkg.NewOIDCManager(
		ctx, "", "",
		"test-github-client", "test-github-secret",
		"http://localhost/callback",
		`{"default_role": "user"}`,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}

	h := NewOIDCHandler(manager, authSvc, userRepo, roleRepo)
	r := gin.New()
	r.GET("/api/auth/oidc/callback", h.Callback)

	// State that was never registered — must be rejected.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=unknown-state&code=test-code", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for unknown state, got %d", http.StatusBadRequest, w.Code)
	}
}
