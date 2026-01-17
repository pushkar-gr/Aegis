package utils

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
	}{
		{
			name:        "Valid password",
			password:    "TestPass123!",
			shouldError: false,
		},
		{
			name:        "Password too long (>72 bytes)",
			password:    strings.Repeat("a", 73),
			shouldError: true,
		},
		{
			name:        "Empty password",
			password:    "",
			shouldError: false, // bcrypt allows empty passwords
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for password: %s", tt.password)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if hash == "" {
					t.Error("Expected non-empty hash")
				}
				// Verify hash starts with bcrypt prefix
				if !strings.HasPrefix(hash, "$2a$") {
					t.Errorf("Invalid bcrypt hash format: %s", hash)
				}
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "TestPassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		expected bool
	}{
		{
			name:     "Correct password",
			password: password,
			hash:     hash,
			expected: true,
		},
		{
			name:     "Incorrect password",
			password: "WrongPassword123!",
			hash:     hash,
			expected: false,
		},
		{
			name:     "Empty password against valid hash",
			password: "",
			hash:     hash,
			expected: false,
		},
		{
			name:     "Valid password against invalid hash",
			password: password,
			hash:     "invalid-hash",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckPasswordHash(tt.password, tt.hash)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
	}{
		{
			name:        "Valid complex password",
			password:    "TestPass123!",
			shouldError: false,
		},
		{
			name:        "Password too short",
			password:    "Tp1!",
			shouldError: true,
		},
		{
			name:        "Password too long",
			password:    strings.Repeat("A", 33) + "a1!",
			shouldError: true,
		},
		{
			name:        "Missing uppercase",
			password:    "testpass123!",
			shouldError: true,
		},
		{
			name:        "Missing lowercase",
			password:    "TESTPASS123!",
			shouldError: true,
		},
		{
			name:        "Missing number",
			password:    "TestPassword!",
			shouldError: true,
		},
		{
			name:        "Missing special character",
			password:    "TestPassword123",
			shouldError: true,
		},
		{
			name:        "Valid with symbols",
			password:    "MyP@ssw0rd!",
			shouldError: false,
		},
		{
			name:        "Valid with multiple special chars",
			password:    "C0mpl3x!P@ss#",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tt.password)
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for password: %s", tt.password)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid password: %v", err)
				}
			}
		})
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "TestPassword123!"

	// Generate two hashes from the same password
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to generate hashes: %v, %v", err1, err2)
	}

	// Hashes should be different (bcrypt uses random salt)
	if hash1 == hash2 {
		t.Error("Expected different hashes due to random salt")
	}

	// Both hashes should validate the same password
	if !CheckPasswordHash(password, hash1) {
		t.Error("Hash1 failed to validate password")
	}
	if !CheckPasswordHash(password, hash2) {
		t.Error("Hash2 failed to validate password")
	}
}
