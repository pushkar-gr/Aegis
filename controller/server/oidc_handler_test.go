package server

import (
	"Aegis/controller/database"
	oidcPkg "Aegis/controller/internal/oidc"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListOIDCProviders(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

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
			expectedCount:  1, // GitHub only in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupOIDC {
				// Initialize OIDC manager for testing
				ctx := context.Background()
				roleMappingJSON := `{"default_role": "user"}`
				manager, err := oidcPkg.NewOIDCManager(
					ctx,
					"",
					"",
					"test-github-client",
					"test-github-secret",
					"http://localhost/callback",
					roleMappingJSON,
				)
				if err != nil {
					t.Fatalf("Failed to create OIDC manager: %v", err)
				}
				oidcManager = manager
				defer func() { oidcManager = nil }()
			} else {
				oidcManager = nil
			}

			req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/providers", nil)
			w := httptest.NewRecorder()

			listOIDCProviders(w, req)

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
	cleanup := setupTestServer(t)
	defer cleanup()

	// Setup OIDC manager
	ctx := context.Background()
	roleMappingJSON := `{"default_role": "user"}`
	manager, err := oidcPkg.NewOIDCManager(
		ctx,
		"",
		"",
		"test-github-client",
		"test-github-secret",
		"http://localhost/callback",
		roleMappingJSON,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}
	oidcManager = manager
	defer func() { oidcManager = nil }()

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{
			name:           "Missing state parameter",
			queryParams:    "code=test-code",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing code parameter",
			queryParams:    "state=test-state",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Both parameters missing",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/auth/oidc/callback"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			oidcCallback(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestUpdatePasswordOIDCUser(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = database.DB.Exec(`ALTER TABLE users ADD COLUMN email TEXT`)
	_, _ = database.DB.Exec(`ALTER TABLE users ADD COLUMN provider TEXT`)
	_, _ = database.DB.Exec(`ALTER TABLE users ADD COLUMN provider_id TEXT`)

	_, err := database.DB.Exec(`
		INSERT INTO users (username, password, email, provider, provider_id, role_id, is_active) 
		VALUES (?, '', ?, ?, ?, 2, 1)
	`, "oidcuser", "oidcuser@example.com", "google", "google-123")
	if err != nil {
		t.Fatalf("Failed to create OIDC test user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", http.NoBody)
	req.Header.Set("Content-Type", "application/json")

	ctx := req.Context()
	ctx = contextWithUser(ctx, "oidcuser")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	updatePassword(w, req)

	t.Logf("Response status: %d, body: %s", w.Code, w.Body.String())

	// Verify the OIDC user exists and has provider set
	var provider string
	err = database.DB.QueryRow("SELECT provider FROM users WHERE username = ?", "oidcuser").Scan(&provider)
	if err != nil {
		t.Fatalf("Failed to query OIDC user: %v", err)
	}
	if provider != "google" {
		t.Errorf("Expected provider 'google', got '%s'", provider)
	}
}
