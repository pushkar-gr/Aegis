package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/utils"
	"context"
	"log"
	"net/http"

	"github.com/justinas/alice"
)

type contextKey string

const userKey contextKey = "username"

// AuthMiddleware validates the JWT token and identifies the user.
// Input:  Cookie "token"
// Output: Next handler (Context + "username") | 401 Unauthorized
func authMiddlewareFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			log.Printf("[middleware] auth failed: missing or unreadable cookie. %v", err)
			if err == http.ErrNoCookie {
				http.Error(w, "Authentication cookie missing", http.StatusUnauthorized)
			} else {
				http.Error(w, "Error retrieving authentication cookie", http.StatusBadRequest)
			}
			return
		}

		username, err := utils.GetUsernameFromToken(cookie.Value, jwtKey)
		if err != nil {
			log.Printf("[middleware] auth failed: token validation error. %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Store the username in the request context for subsequent handlers.
		ctx := context.WithValue(r.Context(), userKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var authMiddleware = alice.New(
	func(h http.Handler) http.Handler { return authMiddlewareFunc(h) },
)

// RootOnly restricts access to the 'root' role.
// Input:  Context "username"
// Output: Next handler | 500 Error | 403 Forbidden
func rootOnlyFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userKey).(string)
		if !ok {
			log.Printf("[middleware] root access denied: user context missing")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		var role string
		err := database.DB.QueryRow(`
			SELECT r.name
			FROM users u
			INNER JOIN roles r ON u.role_id = r.id
			WHERE u.username = ?`, username).Scan(&role)
		if err != nil {
			log.Printf("[middleware] root access denied for user '%s': database error - %v", username, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if role != "root" {
			log.Printf("[middleware] root access denied for user '%s' (Role: %s)", username, role)
			http.Error(w, "Forbidden: root privileges required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var rootOnly = alice.New(
	func(h http.Handler) http.Handler { return authMiddlewareFunc(h) },
	func(h http.Handler) http.Handler { return rootOnlyFunc(h) },
)

// AdminOrRootOnly restricts access to 'admin' or 'root' roles.
// Input:  Context "username"
// Output: Next handler | 500 Error | 403 Forbidden
func adminOrRootOnlyFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userKey).(string)
		if !ok {
			log.Printf("[middleware] admin/root access denied: user context missing")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		var role string
		err := database.DB.QueryRow(`
			SELECT r.name
			FROM users u
			INNER JOIN roles r ON u.role_id = r.id
			WHERE u.username = ?`, username).Scan(&role)
		if err != nil {
			log.Printf("[middleware] admin/root access denied for user '%s': database error - %v", username, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if role != "admin" && role != "root" {
			log.Printf("[middleware] admin/root access denied for user '%s' (Role: %s)", username, role)
			http.Error(w, "Forbidden: root/admin privileges required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var adminOrRootOnly = alice.New(
	func(h http.Handler) http.Handler { return authMiddlewareFunc(h) },
	func(h http.Handler) http.Handler { return adminOrRootOnlyFunc(h) },
)

// SecurityHeadersMiddleware adds protection against common web attacks.
// Input:  Request
// Output: Response with X-Frame-Options, X-Content-Type-Options, HSTS
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}
