package utils

import (
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name       string
		length     int
		shouldWork bool
	}{
		{
			name:       "Standard length 32",
			length:     32,
			shouldWork: true,
		},
		{
			name:       "Short length 16",
			length:     16,
			shouldWork: true,
		},
		{
			name:       "Long length 64",
			length:     64,
			shouldWork: true,
		},
		{
			name:       "Minimum length 1",
			length:     1,
			shouldWork: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.length)

			if tt.shouldWork {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token == "" {
					t.Error("Expected non-empty token")
				}

				// Base64 URL encoded output is longer than input bytes
				if len(token) < tt.length {
					t.Errorf("Expected token length >= %d, got %d", tt.length, len(token))
				}
			}
		})
	}
}

func TestGenerateSecureTokenUniqueness(t *testing.T) {
	// Generate multiple tokens and ensure they're unique
	tokens := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		token, err := GenerateSecureToken(32)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if tokens[token] {
			t.Error("Generated duplicate token")
		}

		tokens[token] = true
	}

	if len(tokens) != iterations {
		t.Errorf("Expected %d unique tokens, got %d", iterations, len(tokens))
	}
}

func TestGenerateSecureTokenDifferentLengths(t *testing.T) {
	// Test that different lengths produce different token sizes
	length1 := 16
	length2 := 32
	length3 := 64

	token1, err := GenerateSecureToken(length1)
	if err != nil {
		t.Fatalf("Failed to generate token1: %v", err)
	}

	token2, err := GenerateSecureToken(length2)
	if err != nil {
		t.Fatalf("Failed to generate token2: %v", err)
	}

	token3, err := GenerateSecureToken(length3)
	if err != nil {
		t.Fatalf("Failed to generate token3: %v", err)
	}

	// Tokens should have different lengths due to base64 encoding
	if len(token1) >= len(token2) {
		t.Error("Expected token1 to be shorter than token2")
	}

	if len(token2) >= len(token3) {
		t.Error("Expected token2 to be shorter than token3")
	}
}

func TestGenerateSecureTokenConcurrency(t *testing.T) {
	// Test concurrent token generation
	const goroutines = 100
	tokens := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			token, err := GenerateSecureToken(32)
			if err != nil {
				t.Errorf("Failed to generate token: %v", err)
			}
			tokens <- token
		}()
	}

	// Collect all tokens
	uniqueTokens := make(map[string]bool)
	for i := 0; i < goroutines; i++ {
		token := <-tokens
		if uniqueTokens[token] {
			t.Error("Generated duplicate token in concurrent execution")
		}
		uniqueTokens[token] = true
	}

	if len(uniqueTokens) != goroutines {
		t.Errorf("Expected %d unique tokens, got %d", goroutines, len(uniqueTokens))
	}
}
