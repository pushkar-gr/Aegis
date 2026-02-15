package models

import "github.com/golang-jwt/jwt/v5"

// User represents a system user entity, containing authentication credentials and an assigned role.
type User struct {
	Id         int    `json:"id"`
	Username   string `json:"username"`
	RoleId     int    `json:"role_id"`
	IsActive   bool   `json:"is_active"`
	Provider   string `json:"provider,omitempty"`    // Authentication provider: "local", "google", "github"
	ProviderID string `json:"provider_id,omitempty"` // Unique identifier from the provider
}

type UserWithCredentials struct {
	Id          int         `json:"id"`
	Credentials Credentials `json:"credentials"`
	RoleId      int         `json:"role_id"`
	IsActive    bool        `json:"is_active"`
}

// Credentials holds the authentication payload (username and password) provided by the client.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// Claims defines the custom JWT claims structure, embedding standard registered claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role,omitempty"`
	RoleID   int    `json:"role_id,omitempty"`
	Provider string `json:"provider,omitempty"` // "local", "google", "github"
	jwt.RegisteredClaims
}
