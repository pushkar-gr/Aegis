package oidc

import (
	"context"
	"strings"
	"testing"
)

func TestNewOIDCManagerErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		googleClientID  string
		googleSecret    string
		githubClientID  string
		githubSecret    string
		redirectURL     string
		roleMappingJSON string
		shouldError     bool
		errorContains   string
	}{
		{
			name:            "Invalid JSON role mapping",
			githubClientID:  "test-client",
			githubSecret:    "test-secret",
			redirectURL:     "http://localhost/callback",
			roleMappingJSON: `{invalid json}`,
			shouldError:     true,
			errorContains:   "failed to parse role mapping rules",
		},
		{
			name:            "No providers configured",
			googleClientID:  "",
			googleSecret:    "",
			githubClientID:  "",
			githubSecret:    "",
			redirectURL:     "http://localhost/callback",
			roleMappingJSON: `{"default_role": "user"}`,
			shouldError:     true,
			errorContains:   "no OIDC providers configured",
		},
		{
			name:            "Valid GitHub provider configuration",
			githubClientID:  "test-github-client",
			githubSecret:    "test-github-secret",
			redirectURL:     "http://localhost/callback",
			roleMappingJSON: `{"default_role": "user"}`,
			shouldError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewOIDCManager(
				ctx,
				tt.googleClientID,
				tt.googleSecret,
				tt.githubClientID,
				tt.githubSecret,
				tt.redirectURL,
				tt.roleMappingJSON,
			)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if manager == nil {
					t.Errorf("Expected manager to be non-nil")
				}
			}
		})
	}
}

func TestOIDCManagerGetProvider(t *testing.T) {
	ctx := context.Background()
	roleMappingJSON := `{"default_role": "user"}`

	manager, err := NewOIDCManager(
		ctx,
		"",
		"",
		"github-client",
		"github-secret",
		"http://localhost/callback",
		roleMappingJSON,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}

	tests := []struct {
		name        string
		provider    string
		shouldError bool
	}{
		{
			name:        "Get GitHub provider",
			provider:    "github",
			shouldError: false,
		},
		{
			name:        "Invalid provider",
			provider:    "invalid",
			shouldError: true,
		},
		{
			name:        "Empty provider name",
			provider:    "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := manager.GetProvider(tt.provider)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if provider != nil {
					t.Errorf("Expected nil provider on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if provider == nil {
					t.Fatalf("Expected non-nil provider")
				}
				if provider.Name != tt.provider {
					t.Errorf("Expected provider name %s, got %s", tt.provider, provider.Name)
				}
			}
		})
	}
}

func TestProviderConfiguration(t *testing.T) {
	ctx := context.Background()
	roleMappingJSON := `{
		"domain_mappings": {
			"@company.com": "user"
		},
		"default_role": "guest"
	}`

	manager, err := NewOIDCManager(
		ctx,
		"",
		"",
		"github-client",
		"github-secret",
		"http://localhost/callback",
		roleMappingJSON,
	)
	if err != nil {
		t.Fatalf("Failed to create OIDC manager: %v", err)
	}

	// Test GitHub provider configuration
	t.Run("GitHub provider config", func(t *testing.T) {
		provider, err := manager.GetProvider("github")
		if err != nil {
			t.Fatalf("Failed to get GitHub provider: %v", err)
		}

		if provider.Config.ClientID != "github-client" {
			t.Errorf("Expected ClientID 'github-client', got '%s'", provider.Config.ClientID)
		}

		if provider.Config.RedirectURL != "http://localhost/callback" {
			t.Errorf("Expected RedirectURL 'http://localhost/callback', got '%s'", provider.Config.RedirectURL)
		}

		if provider.RoleMapping.DefaultRole != "guest" {
			t.Errorf("Expected default role 'guest', got '%s'", provider.RoleMapping.DefaultRole)
		}
	})
}
