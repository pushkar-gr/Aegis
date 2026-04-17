package handler

import (
	"Aegis/controller/internal/models"
	oidcPkg "Aegis/controller/internal/oidc"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/service"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// OIDCHandler handles OIDC authentication endpoints.
type OIDCHandler struct {
	oidcManager *oidcPkg.OIDCManager
	authSvc     service.AuthService
	userRepo    repository.UserRepository
	roleRepo    repository.RoleRepository
	stateMu     sync.Mutex
	states      map[string]time.Time
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(oidcManager *oidcPkg.OIDCManager, authSvc service.AuthService, userRepo repository.UserRepository, roleRepo repository.RoleRepository) *OIDCHandler {
	return &OIDCHandler{
		oidcManager: oidcManager,
		authSvc:     authSvc,
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		states:      make(map[string]time.Time),
	}
}

// ListProviders returns the list of enabled OIDC providers.
func (h *OIDCHandler) ListProviders(c *gin.Context) {
	if h.oidcManager == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC not enabled"})
		return
	}

	providers := make([]string, 0, len(h.oidcManager.Providers))
	for name := range h.oidcManager.Providers {
		providers = append(providers, name)
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// Login initiates the OIDC authentication flow for a provider.
func (h *OIDCHandler) Login(c *gin.Context) {
	if h.oidcManager == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC not enabled"})
		return
	}

	providerName := c.Query("provider")
	if providerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider parameter required"})
		return
	}

	provider, err := h.oidcManager.GetProvider(providerName)
	if err != nil {
		log.Printf("[oidc] provider not found: %s", providerName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
		return
	}

	state := h.generateState()
	h.stateMu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.cleanExpiredStates()
	h.stateMu.Unlock()

	authURL := provider.Config.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles the OAuth2 callback after provider authentication.
func (h *OIDCHandler) Callback(c *gin.Context) {
	if h.oidcManager == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC not enabled"})
		return
	}

	state := c.Query("state")
	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "State parameter missing"})
		return
	}

	h.stateMu.Lock()
	expiry, ok := h.states[state]
	if ok {
		delete(h.states, state)
	}
	h.stateMu.Unlock()

	if !ok || time.Now().After(expiry) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state"})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code parameter missing"})
		return
	}

	var userInfo *oidcUserInfo
	var providerName string
	var err error

	for name, provider := range h.oidcManager.Providers {
		userInfo, err = h.exchangeCodeForUserInfo(c.Request.Context(), provider, code)
		if err == nil {
			providerName = name
			break
		}
		log.Printf("[oidc] failed to exchange code with %s: %v", name, err)
	}

	if userInfo == nil {
		log.Printf("[oidc] callback failed: could not exchange code with any provider")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	provider, _ := h.oidcManager.GetProvider(providerName)
	roleName := provider.MapClaimsToRole(userInfo.Email, userInfo.Groups)

	if roleName == "" || roleName == "none" {
		log.Printf("[oidc] login denied for user '%s' via %s: no role mapping and no default role", userInfo.Email, providerName)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied: no role assigned"})
		return
	}

	user, err := h.getOrCreateOIDCUser(userInfo, providerName, roleName)
	if err != nil {
		log.Printf("[oidc] failed to get or create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !user.IsActive {
		log.Printf("[oidc] login failed for user '%s': account is inactive", user.Username)
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is disabled"})
		return
	}

	expiresAt := time.Now().Add(time.Hour)
	claims := &models.Claims{
		Username: user.Username,
		Role:     roleName,
		RoleID:   user.RoleId,
		Provider: providerName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    "aegis-controller",
			Subject:   user.Username,
		},
	}

	tokenString, err := h.authSvc.GenerateAccessToken(claims)
	if err != nil {
		log.Printf("[oidc] token generation error for user '%s': %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	refreshToken, err := generateSecureToken(32)
	if err != nil {
		log.Printf("[oidc] failed to generate refresh token: %v", err)
	} else {
		refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
		if err := h.userRepo.CreateRefreshToken(refreshToken, user.Id, refreshExpiry); err != nil {
			log.Printf("[oidc] failed to store refresh token: %v", err)
		} else {
			http.SetCookie(c.Writer, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken,
				Expires:  refreshExpiry,
				HttpOnly: true,
				Secure:   true,
				Path:     "/api/auth/refresh",
				SameSite: http.SameSiteStrictMode,
			})
		}
	}

	log.Printf("[oidc] login successful for user '%s' via %s", user.Username, providerName)
	c.Redirect(http.StatusTemporaryRedirect, "/static/pages/dashboard.html")
}

// oidcUserInfo contains user info extracted from an OIDC provider.
type oidcUserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}

// exchangeCodeForUserInfo exchanges an OAuth2 authorization code for user information.
// It supports both standard OIDC providers (via ID token verification) and GitHub OAuth2.
func (h *OIDCHandler) exchangeCodeForUserInfo(ctx context.Context, provider *oidcPkg.Provider, code string) (*oidcUserInfo, error) {
	oauth2Token, err := provider.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	userInfo := &oidcUserInfo{}

	if provider.Verifier != nil {
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return nil, fmt.Errorf("no id_token in token response")
		}
		idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify ID token: %w", err)
		}
		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse claims: %w", err)
		}
		userInfo.Subject = idToken.Subject
		userInfo.Email = claims.Email
		userInfo.EmailVerified = claims.EmailVerified
		userInfo.Name = claims.Name
	} else {
		client := provider.Config.Client(ctx, oauth2Token)
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return nil, fmt.Errorf("failed to get user info: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var githubUser struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
			return nil, fmt.Errorf("failed to decode user info: %w", err)
		}
		userInfo.Subject = fmt.Sprintf("%d", githubUser.ID)
		userInfo.Email = githubUser.Email
		userInfo.Name = githubUser.Name
		userInfo.EmailVerified = true

		if userInfo.Email == "" {
			emailResp, err := client.Get("https://api.github.com/user/emails")
			if err == nil {
				defer func() { _ = emailResp.Body.Close() }()
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if json.NewDecoder(emailResp.Body).Decode(&emails) == nil {
					for _, e := range emails {
						if e.Primary && e.Verified {
							userInfo.Email = e.Email
							break
						}
					}
				}
			}
		}
	}
	return userInfo, nil
}

// getOrCreateOIDCUser looks up an existing OIDC user by provider and subject ID,
// updating their email if needed, or creates a new user with the mapped role on first login.
func (h *OIDCHandler) getOrCreateOIDCUser(userInfo *oidcUserInfo, provider, roleName string) (*models.User, error) {
	user, err := h.userRepo.GetByProviderAndID(provider, userInfo.Subject)
	if err == nil {
		if userInfo.Email != "" {
			if err := h.userRepo.UpdateEmail(user.Id, userInfo.Email); err != nil {
				log.Printf("[oidc] failed to update email for user %s: %v", user.Username, err)
			}
		}
		log.Printf("[oidc] found existing user '%s' from provider '%s'", user.Username, provider)
		return user, nil
	}

	roleID, err := h.roleRepo.GetIDByName(roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role ID for role '%s': %w", roleName, err)
	}

	username := userInfo.Email
	if username == "" {
		username = fmt.Sprintf("%s_%s", provider, userInfo.Subject)
	}

	newUser, err := h.userRepo.CreateOIDCUser(username, provider, userInfo.Subject, userInfo.Email, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	log.Printf("[oidc] created new user '%s' with role '%s' from provider '%s'", username, roleName, provider)
	return newUser, nil
}

// generateState creates a cryptographically random, URL-safe state token for CSRF protection.
func (h *OIDCHandler) generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// cleanExpiredStates removes state tokens that have passed their expiry time.
// Must be called with h.stateMu held.
func (h *OIDCHandler) cleanExpiredStates() {
	now := time.Now()
	for state, expiry := range h.states {
		if now.After(expiry) {
			delete(h.states, state)
		}
	}
}

// generateSecureToken creates a cryptographically random, URL-safe token of n bytes.
func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
