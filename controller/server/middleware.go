package server

import (
	"Aegis/controller/internal/utils"
	"context"
	"log"
	"net/http"
)

type contextKey string

const UserKey contextKey = "username"

// AuthMiddleware validates the JWT token from the cookie and injects the username into the request context.
func AuthMiddleware(next http.Handler, jwtKey []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Authentication cookie missing", http.StatusUnauthorized)
			} else {
				http.Error(w, "Error retrieving authentication cookie", http.StatusBadRequest)
			}
			return
		}
		tokenString := cookie.Value

		username, err := utils.GetUsernameFromToken(tokenString, jwtKey)
		if err != nil {
			// Log the specific validation error internally for debugging.
			log.Printf("Auth failure: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Store the username in the request context for subsequent handlers.
		ctx := context.WithValue(r.Context(), UserKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SecurityHeadersMiddleware adds essential HTTP security headers to every response.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent the site from being embedded in iframes (Clickjacking protection).
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent browsers from mime-sniffing the response type.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Enforce HTTPS usage for one year.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}
