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
	// UsernameRE ensures usernames are alphanumeric and between 5 and 30 characters.
	UsernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")
	jwtKey     []byte
)

// CreateUser handles the creation of new users. It requires Admin privileges.
func CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	val := r.Context().Value(UserKey)
	username, ok := val.(string)

	if !ok {
		log.Println("Error: User context missing in CreateUser handler")
		http.Error(w, "Internal server error: user context missing", http.StatusInternalServerError)
		return
	}

	// Verify the requester has admin privileges.
	role, err := database.GetRole(username)
	if err != nil {
		log.Printf("Database error fetching role for %s: %v", username, err)
		http.Error(w, "Internal server error during authorization", http.StatusInternalServerError)
		return
	}

	if role != "admin" {
		log.Printf("Access denied: User %s attempted to create a user without admin privileges", username)
		http.Error(w, "Forbidden: Admin privileges required", http.StatusForbidden)
		return
	}

	var creatingUser models.User

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&creatingUser)
	if err != nil {
		http.Error(w, "Invalid request body format", http.StatusBadRequest)
		return
	}

	// Validation
	if !UsernameRE.MatchString(creatingUser.Creds.Username) {
		http.Error(w, "Invalid username format", http.StatusBadRequest)
		return
	}
	if err := utils.ValidatePasswordComplexity(creatingUser.Creds.Password); err != nil {
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Securely hash the password before storage.
	creatingUser.Creds.Password, err = utils.HashPassword(creatingUser.Creds.Password)
	if err != nil {
		log.Printf("Error hashing password for new user %s: %v", creatingUser.Creds.Username, err)
		http.Error(w, "Internal server error processing credentials", http.StatusInternalServerError)
		return
	}

	err = database.CreateUser(creatingUser)
	if err != nil {
		log.Printf("Database error creating user %s: %v", creatingUser.Creds.Username, err)
		http.Error(w, "Failed to create user (might already exist)", http.StatusInternalServerError)
		return
	}

	log.Printf("User '%s' created successfully by admin '%s'", creatingUser.Creds.Username, username)
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write([]byte("Logged out successfully")); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// Login authenticates a user and issues a secure JWT cookie.
func Login(w http.ResponseWriter, r *http.Request) {
	// Limit body size to 1MB to prevent DOS attacks.
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds models.Credentials
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedHash string
	row := database.DB.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username)
	err = row.Scan(&storedHash)

	// If user is not found, still perform a dummy hash check to prevent timing attacks to prevent revealing valid usernames.
	if err == sql.ErrNoRows {
		utils.CheckPasswordHash(creds.Password, "$2a$12$DUMMYHASH0000000000000000000000000000000000000000")
		log.Printf("Login failed: User %s not found", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Database error during login for %s: %v", creds.Username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Verify the password.
	if !utils.CheckPasswordHash(creds.Password, storedHash) {
		log.Printf("Login failed: Incorrect password for user %s", creds.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
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
		log.Printf("Error signing token for user %s: %v", creds.Username, err)
		http.Error(w, "Internal server error signing token", http.StatusInternalServerError)
		return
	}

	// Set the JWT as a secure, HTTP-only cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true, // Requires HTTPS
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("User %s logged in successfully", creds.Username)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Logged out successfully")); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// Logout clears the authentication cookie.
func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Invalidate the cookie by setting it to an expired time.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	if _, err := w.Write([]byte("Logged out successfully")); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}
