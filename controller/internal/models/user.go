package models

import "github.com/golang-jwt/jwt/v5"

// User represents a system user entity, containing authentication credentials and an assigned role.
type User struct {
	Creds Credentials `json:"Creds"`
	Role  string      `json:"role"`
}

// Credentials holds the authentication payload (username and password) provided by the client.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// Claims defines the custom JWT claims structure, embedding standard registered claims
// and adding the authenticated username.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}
