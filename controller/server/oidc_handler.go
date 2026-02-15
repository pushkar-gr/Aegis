package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	oidcPkg "Aegis/controller/internal/oidc"
	"Aegis/controller/internal/utils"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCState stores state for the OAuth2 flow
var oidcStates = make(map[string]time.Time)

// listOIDCProviders returns a list of available OIDC providers
func listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	if oidcManager == nil {
		http.Error(w, "OIDC not enabled", http.StatusNotImplemented)
		return
	}

	providers := make([]string, 0, len(oidcManager.Providers))
	for name := range oidcManager.Providers {
		providers = append(providers, name)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
	})
}

// oidcLogin initiates the OIDC authentication flow
func oidcLogin(w http.ResponseWriter, r *http.Request) {
	if oidcManager == nil {
		http.Error(w, "OIDC not enabled", http.StatusNotImplemented)
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		http.Error(w, "Provider parameter required", http.StatusBadRequest)
		return
	}

	provider, err := oidcManager.GetProvider(providerName)
	if err != nil {
		log.Printf("[oidc] provider not found: %s", providerName)
		http.Error(w, "Invalid provider", http.StatusBadRequest)
		return
	}

	// Generate random state for CSRF protection
	state := generateState()
	oidcStates[state] = time.Now().Add(10 * time.Minute)

	// Clean up expired states
	cleanExpiredStates()

	// Redirect to provider
	authURL := provider.Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// oidcCallback handles the OAuth2 callback from the provider
func oidcCallback(w http.ResponseWriter, r *http.Request) {
	if oidcManager == nil {
		http.Error(w, "OIDC not enabled", http.StatusNotImplemented)
		return
	}

	// Verify state to prevent CSRF
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "State parameter missing", http.StatusBadRequest)
		return
	}

	expiry, ok := oidcStates[state]
	if !ok || time.Now().After(expiry) {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}
	delete(oidcStates, state)

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code parameter missing", http.StatusBadRequest)
		return
	}

	// Determine which provider to use
	var userInfo *UserInfo
	var providerName string
	var err error

	for name, provider := range oidcManager.Providers {
		userInfo, err = exchangeCodeForUserInfo(r.Context(), provider, code)
		if err == nil {
			providerName = name
			break
		}
		log.Printf("[oidc] failed to exchange code with %s: %v", name, err)
	}

	if userInfo == nil {
		log.Printf("[oidc] callback failed: could not exchange code with any provider")
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Map claims to role
	provider, _ := oidcManager.GetProvider(providerName)
	roleName := provider.MapClaimsToRole(userInfo.Email, userInfo.Groups)

	// Get or create user
	user, err := getOrCreateOIDCUser(userInfo, providerName, roleName)
	if err != nil {
		log.Printf("[oidc] failed to get or create user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !user.IsActive {
		log.Printf("[oidc] login failed for user '%s': account is inactive", user.Username)
		http.Error(w, "Account is disabled", http.StatusForbidden)
		return
	}

	// Generate JWT token with RS256
	expirationTime := time.Now().Add(jwtTokenLifetime * time.Minute)
	claims := &models.Claims{
		Username: user.Username,
		Role:     roleName,
		RoleID:   user.RoleId,
		Provider: providerName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "aegis-controller",
			Subject:   user.Username,
		},
	}

	tokenString, err := utils.GenerateTokenRS256(claims, jwtPrivateKey)
	if err != nil {
		log.Printf("[oidc] token generation error for user '%s': %v", user.Username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("[oidc] login successful for user '%s' via %s", user.Username, providerName)

	// Redirect to dashboard
	http.Redirect(w, r, "/static/pages/dashboard.html", http.StatusTemporaryRedirect)
}

// UserInfo represents user information from OIDC provider
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}

// exchangeCodeForUserInfo exchanges the authorization code for user information
func exchangeCodeForUserInfo(ctx context.Context, provider *oidcPkg.Provider, code string) (*UserInfo, error) {
	// Exchange code for token
	oauth2Token, err := provider.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	userInfo := &UserInfo{}

	// For Google (OIDC)
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
		// For GitHub (OAuth2 without OIDC)
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

		// Fetch email from emails endpoint
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

// getOrCreateOIDCUser gets or creates a user from OIDC information
func getOrCreateOIDCUser(userInfo *UserInfo, provider, roleName string) (*models.User, error) {
	var user models.User
	err := database.DB.QueryRow(`
		SELECT id, username, role_id, is_active, provider, provider_id
		FROM users
		WHERE provider = ? AND provider_id = ?
	`, provider, userInfo.Subject).Scan(&user.Id, &user.Username, &user.RoleId, &user.IsActive, &user.Provider, &user.ProviderID)

	if err == sql.ErrNoRows {
		// Create user
		var roleID int
		err := database.DB.QueryRow("SELECT id FROM roles WHERE name = ?", roleName).Scan(&roleID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role ID: %w", err)
		}

		// Generate username from email
		username := userInfo.Email
		if username == "" {
			username = fmt.Sprintf("%s_%s", provider, userInfo.Subject)
		}

		// Insert new user
		result, err := database.DB.Exec(`
			INSERT INTO users (username, password, role_id, is_active, provider, provider_id, email)
			VALUES (?, NULL, ?, 1, ?, ?, ?)
		`, username, roleID, provider, userInfo.Subject, userInfo.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		id, _ := result.LastInsertId()
		user = models.User{
			Id:         int(id),
			Username:   username,
			RoleId:     roleID,
			IsActive:   true,
			Provider:   provider,
			ProviderID: userInfo.Subject,
		}

		log.Printf("[oidc] created new user '%s' with role '%s' from provider '%s'", username, roleName, provider)
	} else if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	} else {
		if userInfo.Email != "" {
			_, err := database.DB.Exec("UPDATE users SET email = ? WHERE id = ?", userInfo.Email, user.Id)
			if err != nil {
				log.Printf("[oidc] failed to update email for user %s: %v", user.Username, err)
			}
		}
		log.Printf("[oidc] found existing user '%s' from provider '%s'", user.Username, provider)
	}

	return &user, nil
}

// generateState generates a random state string for CSRF protection
func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// cleanExpiredStates removes expired state entries
func cleanExpiredStates() {
	now := time.Now()
	for state, expiry := range oidcStates {
		if now.After(expiry) {
			delete(oidcStates, state)
		}
	}
}
