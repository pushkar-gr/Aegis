package utils

import (
	"Aegis/controller/internal/models"
	"crypto/rand"
	"crypto/rsa"
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

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return privKey
}

func TestGenerateTokenRS256(t *testing.T) {
	privKey := generateTestRSAKey(t)
	testUsername := "testuser"

	claims := &models.Claims{
		Username: testUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "aegis-controller",
		},
	}

	tokenString, err := GenerateTokenRS256(claims, privKey)
	if err != nil {
		t.Fatalf("GenerateTokenRS256 failed: %v", err)
	}
	if tokenString == "" {
		t.Error("Expected non-empty token string")
	}

	// Verify the token can be parsed with the public key
	username, err := GetUsernameFromTokenRS256(tokenString, &privKey.PublicKey)
	if err != nil {
		t.Errorf("GetUsernameFromTokenRS256 failed: %v", err)
	}
	if username != testUsername {
		t.Errorf("Expected username %s, got %s", testUsername, username)
	}
}

func TestGetUsernameFromTokenRS256(t *testing.T) {
	privKey := generateTestRSAKey(t)
	testUsername := "rs256user"

	// Create a valid RS256 token
	claims := &models.Claims{
		Username: testUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "aegis-controller",
		},
	}
	validToken, err := GenerateTokenRS256(claims, privKey)
	if err != nil {
		t.Fatalf("Failed to create RS256 token: %v", err)
	}

	// Create an expired RS256 token
	expiredClaims := &models.Claims{
		Username: testUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	expiredToken, err := GenerateTokenRS256(expiredClaims, privKey)
	if err != nil {
		t.Fatalf("Failed to create expired RS256 token: %v", err)
	}

	// Create a different RSA key pair for wrong key test
	otherKey := generateTestRSAKey(t)

	tests := []struct {
		name         string
		tokenString  string
		shouldError  bool
		expectedUser string
	}{
		{
			name:         "Valid RS256 token",
			tokenString:  validToken,
			shouldError:  false,
			expectedUser: testUsername,
		},
		{
			name:        "Expired RS256 token",
			tokenString: expiredToken,
			shouldError: true,
		},
		{
			name:        "Wrong public key",
			tokenString: validToken,
			// Using other key's public key to test wrong key scenario
			shouldError: true,
		},
		{
			name:        "Malformed token",
			tokenString: "not.a.valid.token",
			shouldError: true,
		},
		{
			name:        "Empty token",
			tokenString: "",
			shouldError: true,
		},
		{
			name: "HMAC token rejected by RS256 verifier",
			tokenString: func() string {
				hmacClaims := &models.Claims{
					Username: testUsername,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
					},
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodHS256, hmacClaims)
				s, _ := tok.SignedString([]byte("secret"))
				return s
			}(),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pubKey *rsa.PublicKey
			if tt.name == "Wrong public key" {
				pubKey = &otherKey.PublicKey
			} else {
				pubKey = &privKey.PublicKey
			}
			username, err := GetUsernameFromTokenRS256(tt.tokenString, pubKey)
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.expectedUser != "" && username != tt.expectedUser {
					t.Errorf("Expected username %s, got %s", tt.expectedUser, username)
				}
			}
		})
	}
}

func TestGetUsernameFromTokenRS256WrongKey(t *testing.T) {
	privKey := generateTestRSAKey(t)
	otherKey := generateTestRSAKey(t)

	claims := &models.Claims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	tokenString, err := GenerateTokenRS256(claims, privKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, err = GetUsernameFromTokenRS256(tokenString, &otherKey.PublicKey)
	if err == nil {
		t.Error("Expected error when verifying with wrong public key, but got none")
	}
}
