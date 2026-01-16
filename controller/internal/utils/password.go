package utils

import (
	"errors"
	"fmt"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	// HashingCost defines the computational complexity (logarithmic) for bcrypt.
	// Cost 12 is currently considered secure against brute-force attacks on modern hardware.
	HashingCost = 12
	// BcryptMaxBytes is the hard limit for password length in bcrypt (72 bytes).
	BcryptMaxBytes = 72
)

// HashPassword generates a secure bcrypt hash of the provided plain-text password.
// It returns an error if the password length exceeds the bcrypt maximum.
func HashPassword(password string) (string, error) {
	// Bcrypt has a limitation where it truncates passwords longer than 72 bytes.
	// We explicitly reject them to prevent users from thinking their long password is fully used.
	if len(password) > BcryptMaxBytes {
		return "", fmt.Errorf("password exceeds maximum allowed length of %d bytes", BcryptMaxBytes)
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), HashingCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckPasswordHash securely compares a plain-text password with a bcrypt hash.
// It returns true only if the password matches the hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePasswordComplexity valideates user password.
// It enforces: 8-32 chars, 1 upper, 1 lower, 1 number, 1 special.
func ValidatePasswordComplexity(password string) error {
	if len(password) < 8 || len(password) > 32 {
		return errors.New("password length must be between 8 and 32 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain at least one uppercase, one lowercase, one number, and one special character")
	}

	return nil
}
