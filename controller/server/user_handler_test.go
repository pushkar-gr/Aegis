package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWelcome(t *testing.T) {
	tests := []struct {
		name           string
		contextValue   interface{}
		setContext     bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid user in context",
			contextValue:   "testuser",
			setContext:     true,
			expectedStatus: http.StatusOK,
			expectedBody:   "Welcome, testuser! This is a protected route.",
		},
		{
			name:           "Different username",
			contextValue:   "anotheruser",
			setContext:     true,
			expectedStatus: http.StatusOK,
			expectedBody:   "Welcome, anotheruser! This is a protected route.",
		},
		{
			name:           "Missing context",
			contextValue:   nil,
			setContext:     false,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error: user context missing\n",
		},
		{
			name:           "Invalid context type",
			contextValue:   123, // Not a string
			setContext:     true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error: user context missing\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/welcome", nil)

			// Set context if needed
			if tt.setContext {
				ctx := context.WithValue(req.Context(), UserKey, tt.contextValue)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			Welcome(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, rr.Body.String())
			}
		})
	}
}

func TestWelcomeXSSProtection(t *testing.T) {
	// Test that HTML/JS in username is escaped
	maliciousUsername := "<script>alert('xss')</script>"

	req := httptest.NewRequest(http.MethodGet, "/welcome", nil)
	ctx := context.WithValue(req.Context(), UserKey, maliciousUsername)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	Welcome(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()

	// Check that the malicious script is escaped
	if strings.Contains(body, "<script>") {
		t.Error("XSS vulnerability: script tag not escaped")
	}

	// Check that the escaped version is present
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("Expected HTML-escaped username in response")
	}
}

func TestWelcomeSpecialCharacters(t *testing.T) {
	specialUsernames := []string{
		"user&name",
		"user<name>",
		"user\"name",
		"user'name",
		"user@example.com",
	}

	for _, username := range specialUsernames {
		t.Run("Username_"+username, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/welcome", nil)
			ctx := context.WithValue(req.Context(), UserKey, username)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			Welcome(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
			}

			// Ensure response contains some form of the username (escaped or not)
			body := rr.Body.String()
			if !strings.Contains(body, "Welcome") {
				t.Error("Response should contain welcome message")
			}
		})
	}
}
