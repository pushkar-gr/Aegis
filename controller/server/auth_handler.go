package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// UsernameRE enforces 5-30 char alphanumeric usernames.
	UsernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")
	jwtKey     []byte
)

// Login validates credentials and checks if the user is active.
// Input:  {"username": "jdoe", "password": "secret_password"}
// Output: 200 OK (Set-Cookie: token=...) | 401 Unauthorized | 403 Forbidden (Inactive) | 400 Bad Request
func login(w http.ResponseWriter, r *http.Request) {
	// Cap body at 1MB to prevent DoS.
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var creds models.Credentials
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&creds); err != nil {
		log.Printf("Login error: failed to decode body. %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedHash string
	var isActive bool
	row := database.DB.QueryRow("SELECT password, is_active FROM users WHERE username = ?", creds.Username)
	err := row.Scan(&storedHash, &isActive)

	// Determine if user exists. Always run a hash check to prevent timing attacks.
	if err == sql.ErrNoRows {
		utils.CheckPasswordHash(creds.Password, "$2a$12$DUMMYHASH0000000000000000000000000000000000000000")
		log.Printf("Login failed: User '%s' not found", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Login DB error for user '%s': %v", creds.Username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Verify password against stored hash.
	if !utils.CheckPasswordHash(creds.Password, storedHash) {
		log.Printf("Login failed: Incorrect password for '%s'", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !isActive {
		log.Printf("Login failed: User '%s' is inactive", creds.Username)
		http.Error(w, "Account is disabled", http.StatusForbidden)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &models.Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "go-auth-system",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Login token signing error for '%s': %v", creds.Username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set secure, HTTP-only cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("User '%s' logged in successfully", creds.Username)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged in successfully"))
}

// Logout clears the auth cookie.
// Input:  Empty body (Cookie required in header)
// Output: 200 OK (Set-Cookie: token=; Expires=1970...)
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	// Get user from context (set by middleware).
	val := r.Context().Value(userKey)
	username, ok := val.(string)
	if ok {
		log.Printf("User '%v' logged out", username)
	} else {
		log.Println("Logout called (no active user context found)")
	}

	w.Write([]byte("Logged out successfully"))
}

// UpdatePassword verifies the old password and sets a new one.
// Input:  {"old_password": "current_secret", "new_password": "new_secret_123"}
// Output: 200 OK | 400 Bad Request (Weak password) | 401 Unauthorized
func updatePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("UpdatePassword error: bad JSON body. %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Enforce complexity rules.
	if err := utils.ValidatePasswordComplexity(req.NewPassword); err != nil {
		log.Printf("UpdatePassword failed: weak password. %v", err)
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get user from context (set by middleware).
	val := r.Context().Value(userKey)
	username, ok := val.(string)
	if !ok {
		log.Println("UpdatePassword critical: User context missing or invalid")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch current hash.
	var storedHash string
	row := database.DB.QueryRow("SELECT password FROM users WHERE username = ?", username)
	err := row.Scan(&storedHash)
	if err != nil {
		log.Printf("UpdatePassword DB lookup error for '%s': %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Verify the old password before allowing a change.
	if !utils.CheckPasswordHash(req.OldPassword, storedHash) {
		log.Printf("UpdatePassword failed: wrong old password for '%s'", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Hash the new password.
	newHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("UpdatePassword hashing error for '%s': %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Update DB.
	res, err := database.DB.Exec("UPDATE users SET password = ? WHERE username = ?", newHash, username)
	if err != nil {
		log.Printf("UpdatePassword DB update failed for '%s': %v", username, err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		log.Printf("UpdatePassword warning: No rows affected for '%s'", username)
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	log.Printf("Password updated successfully for user: '%s'", username)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password updated successfully"))
}
