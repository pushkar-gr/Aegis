package server

import (
	"Aegis/controller/internal/models"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthMiddleware(t *testing.T) {
	testKey := []byte("test-jwt-secret")

	// Create a valid token
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &models.Claims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "go-auth-system",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validTokenString, err := token.SignedString(testKey)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Create an expired token
	expiredClaims := &models.Claims{
		Username: "expireduser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			Issuer:    "go-auth-system",
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString(testKey)
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	// Create a simple handler to test the middleware
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(UserKey)
		username, ok := val.(string)
		if !ok {
			t.Error("Username not found in context")
			http.Error(w, "Context error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, " + username))
	})

	tests := []struct {
		name           string
		cookieValue    string
		setCookie      bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid token",
			cookieValue:    validTokenString,
			setCookie:      true,
			expectedStatus: http.StatusOK,
			expectedBody:   "Hello, testuser",
		},
		{
			name:           "No cookie",
			cookieValue:    "",
			setCookie:      false,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authentication cookie missing\n",
		},
		{
			name:           "Expired token",
			cookieValue:    expiredTokenString,
			setCookie:      true,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid or expired token\n",
		},
		{
			name:           "Invalid token",
			cookieValue:    "invalid.token.string",
			setCookie:      true,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid or expired token\n",
		},
		{
			name:           "Empty token",
			cookieValue:    "",
			setCookie:      true,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid or expired token\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set cookie if needed
			if tt.setCookie {
				req.AddCookie(&http.Cookie{
					Name:  "token",
					Value: tt.cookieValue,
				})
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Wrap the handler with middleware
			handler := AuthMiddleware(testHandler, testKey)

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check body
			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, rr.Body.String())
			}
		})
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	// Create a simple test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	// Wrap the handler with security headers middleware
	handler := SecurityHeadersMiddleware(testHandler)

	// Serve the request
	handler.ServeHTTP(rr, req)

	// Check that security headers are set
	tests := []struct {
		header   string
		expected string
	}{
		{
			header:   "X-Frame-Options",
			expected: "DENY",
		},
		{
			header:   "X-Content-Type-Options",
			expected: "nosniff",
		},
		{
			header:   "Strict-Transport-Security",
			expected: "max-age=63072000; includeSubDomains",
		},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := rr.Header().Get(tt.header)
			if got != tt.expected {
				t.Errorf("Expected header %s to be %q, got %q", tt.header, tt.expected, got)
			}
		})
	}

	// Check response status and body
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("Expected body %q, got %q", "OK", rr.Body.String())
	}
}

func TestAuthMiddlewareWithDifferentSigningKey(t *testing.T) {
	correctKey := []byte("correct-key")
	wrongKey := []byte("wrong-key")

	// Create a token with correct key
	claims := &models.Claims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(correctKey)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Try to validate with wrong key
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: tokenString,
	})

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(testHandler, wrongKey)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d with wrong key, got %d", http.StatusUnauthorized, rr.Code)
	}
}
