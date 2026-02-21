package utils

import (
	"Aegis/controller/internal/models"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GetUsernameFromToken verifies the JWT token string using the provided secret key
// and extracts the username claim. It enforces the HMAC signing method.
func GetUsernameFromToken(tokenString string, jwtKey []byte) (string, error) {
	// Parse the token, validating the signature in the callback function.
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (any, error) {
		// Explicitly verify the signing method is HMAC to prevent critical vulnerabilities
		// where an attacker could switch the algorithm to 'None'.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("token parsing failed: %w", err)
	}

	// Validate the token and type-cast the claims.
	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims.Username, nil
	}

	return "", errors.New("token is invalid or claims could not be parsed")
}

// GetUsernameFromTokenRS256 verifies the JWT token string using RS256 (RSA) asymmetric signing and retuns username.
func GetUsernameFromTokenRS256(tokenString string, publicKey *rsa.PublicKey) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("token parsing failed: %w", err)
	}

	// Validate the token and type-cast the claims.
	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims.Username, nil
	}

	return "", errors.New("token is invalid or claims could not be parsed")
}

// GenerateTokenRS256 creates a new JWT token signed with RS256 using the private key.
func GenerateTokenRS256(claims *models.Claims, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}
