package utils

import (
	"Aegis/controller/internal/models"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGetUsernameFromToken(t *testing.T) {
	testKey := []byte("test-secret-key")
	testUsername := "testuser"

	// Create a valid token
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &models.Claims{
		Username: testUsername,
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
		Username: testUsername,
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

	// Create a token with wrong signing method (None algorithm attack)
	// Note: This intentionally tests a security vulnerability to ensure it's properly prevented
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	noneTokenString, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to create none token: %v", err)
	}

	tests := []struct {
		name         string
		tokenString  string
		jwtKey       []byte
		shouldError  bool
		expectedUser string
	}{
		{
			name:         "Valid token",
			tokenString:  validTokenString,
			jwtKey:       testKey,
			shouldError:  false,
			expectedUser: testUsername,
		},
		{
			name:         "Expired token",
			tokenString:  expiredTokenString,
			jwtKey:       testKey,
			shouldError:  true,
			expectedUser: "",
		},
		{
			name:         "Invalid signature",
			tokenString:  validTokenString,
			jwtKey:       []byte("wrong-key"),
			shouldError:  true,
			expectedUser: "",
		},
		{
			name:         "Malformed token",
			tokenString:  "not.a.valid.token",
			jwtKey:       testKey,
			shouldError:  true,
			expectedUser: "",
		},
		{
			name:         "Empty token",
			tokenString:  "",
			jwtKey:       testKey,
			shouldError:  true,
			expectedUser: "",
		},
		{
			name:         "None algorithm token (security test)",
			tokenString:  noneTokenString,
			jwtKey:       testKey,
			shouldError:  true,
			expectedUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := GetUsernameFromToken(tt.tokenString, tt.jwtKey)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if username != tt.expectedUser {
					t.Errorf("Expected username %s, got %s", tt.expectedUser, username)
				}
			}
		})
	}
}

func TestGetUsernameFromTokenWithDifferentClaims(t *testing.T) {
	testKey := []byte("test-secret-key")

	// Test with minimal claims
	minimalClaims := &models.Claims{
		Username: "minimaluser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	minimalToken := jwt.NewWithClaims(jwt.SigningMethodHS256, minimalClaims)
	minimalTokenString, err := minimalToken.SignedString(testKey)
	if err != nil {
		t.Fatalf("Failed to create minimal token: %v", err)
	}

	username, err := GetUsernameFromToken(minimalTokenString, testKey)
	if err != nil {
		t.Errorf("Failed to parse valid minimal token: %v", err)
	}
	if username != "minimaluser" {
		t.Errorf("Expected username 'minimaluser', got '%s'", username)
	}
}

func TestGetUsernameFromTokenSigningMethods(t *testing.T) {
	testKey := []byte("test-secret-key")
	testUsername := "testuser"
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &models.Claims{
		Username: testUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Test different HMAC signing methods (should all work)
	signingMethods := []jwt.SigningMethod{
		jwt.SigningMethodHS256,
		jwt.SigningMethodHS384,
		jwt.SigningMethodHS512,
	}

	for _, method := range signingMethods {
		t.Run(method.Alg(), func(t *testing.T) {
			token := jwt.NewWithClaims(method, claims)
			tokenString, err := token.SignedString(testKey)
			if err != nil {
				t.Fatalf("Failed to create token with %s: %v", method.Alg(), err)
			}

			username, err := GetUsernameFromToken(tokenString, testKey)
			if err != nil {
				t.Errorf("Failed to parse token with %s: %v", method.Alg(), err)
			}
			if username != testUsername {
				t.Errorf("Expected username %s, got %s", testUsername, username)
			}
		})
	}
}
