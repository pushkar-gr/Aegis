package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// Provider represents an OIDC provider configuration
type Provider struct {
	Name        string
	Config      *oauth2.Config
	Verifier    *oidc.IDTokenVerifier
	RoleMapping *RoleMappingRules
}

// RoleMappingRules defines how OIDC claims maps to roles
type RoleMappingRules struct {
	DomainMappings map[string]string `json:"domain_mappings"` // email domain -> role name
	GroupMappings  map[string]string `json:"group_mappings"`  // OIDC group -> role name
	DefaultRole    string            `json:"default_role"`
}

// Manages multiple OIDC providers
type OIDCManager struct {
	Providers map[string]*Provider
}

// NewOIDCManager creates a new OIDC manager
func NewOIDCManager(ctx context.Context, googleClientID, googleSecret, githubClientID, githubSecret, redirectURL, roleMappingJSON string) (*OIDCManager, error) {
	manager := &OIDCManager{
		Providers: make(map[string]*Provider),
	}

	var roleMapping RoleMappingRules
	if err := json.Unmarshal([]byte(roleMappingJSON), &roleMapping); err != nil {
		return nil, fmt.Errorf("failed to parse role mapping rules: %w", err)
	}

	if roleMapping.DefaultRole == "" {
		roleMapping.DefaultRole = "user"
	}

	if googleClientID != "" && googleSecret != "" {
		googleProvider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Google OIDC provider: %w", err)
		}

		manager.Providers["google"] = &Provider{
			Name: "google",
			Config: &oauth2.Config{
				ClientID:     googleClientID,
				ClientSecret: googleSecret,
				RedirectURL:  redirectURL,
				Endpoint:     google.Endpoint,
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			},
			Verifier: googleProvider.Verifier(&oidc.Config{
				ClientID: googleClientID,
			}),
			RoleMapping: &roleMapping,
		}
		log.Printf("[INFO] Google OIDC provider initialized")
	}

	if githubClientID != "" && githubSecret != "" {
		manager.Providers["github"] = &Provider{
			Name: "github",
			Config: &oauth2.Config{
				ClientID:     githubClientID,
				ClientSecret: githubSecret,
				RedirectURL:  redirectURL,
				Endpoint:     github.Endpoint,
				Scopes:       []string{"read:user", "user:email"},
			},
			RoleMapping: &roleMapping,
		}
		log.Printf("[INFO] GitHub OAuth2 provider initialized")
	}

	if len(manager.Providers) == 0 {
		return nil, fmt.Errorf("no OIDC providers configured")
	}

	return manager, nil
}

// GetProvider returns a provider name
func (m *OIDCManager) GetProvider(name string) (*Provider, error) {
	provider, ok := m.Providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return provider, nil
}

// MapClaimsToRole gets the role based on OIDC claims
func (p *Provider) MapClaimsToRole(email string, groups []string) string {
	if role, ok := p.RoleMapping.DomainMappings[email]; ok {
		return role
	}

	if email != "" {
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domain := "@" + parts[1]
			if role, ok := p.RoleMapping.DomainMappings[domain]; ok {
				return role
			}
		}
	}

	for _, group := range groups {
		if role, ok := p.RoleMapping.GroupMappings[group]; ok {
			return role
		}
	}

	return p.RoleMapping.DefaultRole
}
