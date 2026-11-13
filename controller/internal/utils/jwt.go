package utils

import (
	"Aegis/controller/internal/models"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const TokenIssuer = "aegis-controller"

// TokenVerifier validates a token string and returns the username it carries.
type TokenVerifier func(tokenString string) (string, error)

func NewHMACVerifier(key []byte) TokenVerifier {
	return func(tok string) (string, error) { return GetUsernameFromToken(tok, key) }
}

func NewRSAVerifier(pub *rsa.PublicKey) TokenVerifier {
	return func(tok string) (string, error) { return GetUsernameFromTokenRS256(tok, pub) }
}

func parseUsername(tokenString string, keyFunc jwt.Keyfunc, alg string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, keyFunc,
		jwt.WithValidMethods([]string{alg}),
		jwt.WithIssuer(models.TokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", fmt.Errorf("token parsing failed: %w", err)
	}
	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims.Username, nil
	}
	return "", errors.New("token is invalid or claims could not be parsed")
}

// GetUsernameFromToken verifies an HS256 token and returns the username.
func GetUsernameFromToken(tokenString string, jwtKey []byte) (string, error) {
	return parseUsername(tokenString, func(*jwt.Token) (any, error) { return jwtKey, nil }, "HS256")
}

// GetUsernameFromTokenRS256 verifies an RS256 token and returns the username.
func GetUsernameFromTokenRS256(tokenString string, publicKey *rsa.PublicKey) (string, error) {
	return parseUsername(tokenString, func(*jwt.Token) (any, error) { return publicKey, nil }, "RS256")
}

// GenerateTokenHS256 creates a new JWT signed with HS256 using the shared secret.
func GenerateTokenHS256(claims *models.Claims, key []byte) (string, error) {
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
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
