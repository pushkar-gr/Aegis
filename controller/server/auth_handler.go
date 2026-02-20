package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// login validates user credentials and creates an authenticated session.
// Request: {"username": "jdoe", "password": "secret_password"}
// Response: 200 OK with auth cookie | 400 Bad Request | 401 Unauthorized | 403 Forbidden
func login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var creds models.Credentials
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&creds); err != nil {
		log.Printf("[auth] login failed for user '%s': invalid request body - %v", creds.Username, err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	storedHash, isActive, err := database.GetUserCredentials(creds.Username)

	if err == sql.ErrNoRows {
		// Run a dummy hash check to prevent timing attacks
		utils.CheckPasswordHash(creds.Password, "$2a$12$DUMMYHASH0000000000000000000000000000000000000000")
		log.Printf("[auth] login failed for user '%s': user not found", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("[auth] login failed for user '%s': database error - %v", creds.Username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !utils.CheckPasswordHash(creds.Password, storedHash) {
		log.Printf("[auth] login failed for user '%s': incorrect password", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !isActive {
		log.Printf("[auth] login failed for user '%s': account is inactive", creds.Username)
		http.Error(w, "Account is disabled", http.StatusForbidden)
		return
	}

	expirationTime := time.Now().Add(jwtTokenLifetime * time.Minute)

	// Get user role name
	var roleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM roles r
		INNER JOIN users u ON u.role_id = r.id
		WHERE u.username = ?`, creds.Username).Scan(&roleName)
	if err != nil {
		log.Printf("[auth] failed to get role for user '%s': %v", creds.Username, err)
		roleName = ""
	}

	claims := &models.Claims{
		Username: creds.Username,
		Role:     roleName,
		RoleID:   0,
		Provider: "local",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "aegis-controller",
			Subject:   creds.Username,
		},
	}

	// Get role ID for the claims
	err = database.DB.QueryRow(`
		SELECT r.id FROM roles r
		INNER JOIN users u ON u.role_id = r.id
		WHERE u.username = ?`, creds.Username).Scan(&claims.RoleID)
	if err != nil {
		log.Printf("[auth] failed to get role ID for user '%s': %v", creds.Username, err)
	}

	var tokenString string
	if jwtPrivateKey != nil {
		tokenString, err = utils.GenerateTokenRS256(claims, jwtPrivateKey)
	} else {
		tokenString, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	}

	if err != nil {
		log.Printf("[auth] login failed for user '%s': token generation error - %v", creds.Username, err)
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

	// Generate and store refresh token
	refreshToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		log.Printf("[auth] failed to generate refresh token for user '%s': %v", creds.Username, err)
	} else {
		var userID int
		err = database.DB.QueryRow("SELECT id FROM users WHERE username = ?", creds.Username).Scan(&userID)
		if err != nil {
			log.Printf("[auth] failed to get user ID for refresh token: %v", err)
		} else {
			refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
			err = database.CreateRefreshToken(refreshToken, userID, refreshExpiry)
			if err != nil {
				log.Printf("[auth] failed to store refresh token: %v", err)
			} else {
				http.SetCookie(w, &http.Cookie{
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
	}

	log.Printf("[auth] login successful for user '%s'", creds.Username)

	// Return user info with role
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{
		"message": "Logged in successfully",
		"role":    roleName,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[auth] failed to write response: %v", err)
	}
}

// Logout clears the auth cookie.
// Input:  Empty body (Cookie required in header)
// Output: 200 OK (Set-Cookie: token=; Expires=1970...)
func logout(w http.ResponseWriter, r *http.Request) {
	var username string
	if user, ok := r.Context().Value(userKey).(string); ok {
		username = user

		// Delete all refresh tokens for the user
		var userID int
		err := database.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
		if err == nil {
			if err := database.DeleteUserRefreshTokens(userID); err != nil {
				log.Printf("[auth] failed to delete refresh tokens for user '%s': %v", username, err)
			}
		}
	}

	// Clear access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/api/auth/refresh",
	})

	if username != "" {
		log.Printf("[auth] user '%s' logged out", username)
	} else {
		log.Println("[auth] logout called (no active user context found)")
	}

	if _, err := w.Write([]byte("Logged out successfully")); err != nil {
		log.Printf("[auth] failed to write response: %v", err)
	}
}

// updatePassword changes a user's password after verifying the old one.
// Request: {"old_password": "current", "new_password": "new123"}
// Response: 200 OK | 400 Bad Request | 401 Unauthorized | 403 Forbidden
func updatePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[auth] update password failed: invalid request body - %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := utils.ValidatePasswordComplexity(req.NewPassword); err != nil {
		log.Printf("[auth] update password failed: password too weak - %v", err)
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	username, ok := r.Context().Value(userKey).(string)
	if !ok {
		log.Printf("[auth] update password failed: user context missing")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if user is OIDC user
	var provider sql.NullString
	err := database.DB.QueryRow("SELECT COALESCE(provider, 'local') FROM users WHERE username = ?", username).Scan(&provider)
	if err != nil {
		// local provider user
		provider.String = "local"
		provider.Valid = true
		log.Printf("[auth] provider column not found, assuming local auth for user '%s'", username)
	}

	if provider.Valid && provider.String != "local" {
		log.Printf("[auth] update password denied for OIDC user '%s' (provider: %s)", username, provider.String)
		http.Error(w, "Password changes not allowed for SSO users", http.StatusForbidden)
		return
	}

	storedHash, err := database.GetPasswordHash(username)
	if err != nil {
		log.Printf("[auth] update password failed for user '%s': database error - %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !utils.CheckPasswordHash(req.OldPassword, storedHash) {
		log.Printf("[auth] update password failed for user '%s': incorrect old password", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	newHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("[auth] update password failed for user '%s': hashing error - %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	rows, err := database.UpdateUserPassword(username, newHash)
	if err != nil {
		log.Printf("[auth] update password failed for user '%s': update error - %v", username, err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	if rows == 0 {
		log.Printf("[auth] update password failed for user '%s': user not found", username)
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	log.Printf("[auth] password updated successfully for user '%s'", username)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Password updated successfully")); err != nil {
		log.Printf("[auth] failed to write response: %v", err)
	}
}

// getCurrentUser returns the current user's info including role
// Response: 200 OK with user info | 401 Unauthorized | 500 Internal Server Error
func getCurrentUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	username, ok := r.Context().Value(userKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		RoleId   int    `json:"role_id"`
	}

	err := database.DB.QueryRow(`
		SELECT u.username, r.name, r.id
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.username = ?`, username).Scan(&user.Username, &user.Role, &user.RoleId)

	if err != nil {
		log.Printf("[auth] get current user failed for '%s': %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("[auth] failed to encode response: %v", err)
	}
}

// refreshToken generates a new access token using a refresh token
// Response: 200 OK with new token | 401 Unauthorized | 500 Internal Server Error
func refreshToken(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Printf("[auth] refresh failed: missing refresh token cookie")
		http.Error(w, "Refresh token missing", http.StatusUnauthorized)
		return
	}

	// Validate refresh token and get user ID
	userID, err := database.GetRefreshToken(cookie.Value)
	if err != nil {
		log.Printf("[auth] refresh failed: invalid or expired refresh token")
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	var username, roleName, provider string
	var roleID int
	var isActive bool
	err = database.DB.QueryRow(`
		SELECT u.username, r.name, r.id, u.is_active, u.provider
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, userID).Scan(&username, &roleName, &roleID, &isActive, &provider)

	if err != nil {
		log.Printf("[auth] refresh failed: user not found")
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if !isActive {
		log.Printf("[auth] refresh failed for user '%s': account is inactive", username)
		http.Error(w, "Account is disabled", http.StatusForbidden)
		return
	}

	// Generate new access token
	expirationTime := time.Now().Add(jwtTokenLifetime * time.Minute)
	claims := &models.Claims{
		Username: username,
		Role:     roleName,
		RoleID:   roleID,
		Provider: provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "aegis-controller",
			Subject:   username,
		},
	}

	var tokenString string
	// Use RS256 else fall back to HS256
	if jwtPrivateKey != nil {
		tokenString, err = utils.GenerateTokenRS256(claims, jwtPrivateKey)
	} else {
		tokenString, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	}

	if err != nil {
		log.Printf("[auth] refresh failed for user '%s': token generation error - %v", username, err)
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

	log.Printf("[auth] token refreshed successfully for user '%s'", username)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Token refreshed successfully",
		"role":    roleName,
	})
}
