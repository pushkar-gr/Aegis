package utils

import (
	"slices"
	"testing"
)

// TestResolveHostname tests the hostname resolution function
func TestResolveHostname(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		expectError bool
		validateIP  func(t *testing.T, ips []string)
	}{
		{
			name:        "Resolve localhost",
			hostname:    "localhost",
			expectError: false,
			validateIP: func(t *testing.T, ips []string) {
				if len(ips) == 0 {
					t.Error("Expected at least one IP address")
				}
				// localhost should resolve to 127.0.0.1
				if !slices.Contains(ips, "127.0.0.1") {
					t.Errorf("Expected localhost to resolve to 127.0.0.1, got %v", ips)
				}
			},
		},
		{
			name:        "Resolve IP address directly",
			hostname:    "192.168.1.1",
			expectError: false,
			validateIP: func(t *testing.T, ips []string) {
				if len(ips) == 0 {
					t.Error("Expected at least one IP address")
				}
				if ips[0] != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", ips[0])
				}
			},
		},
		{
			name:        "Non-existent domain",
			hostname:    "this-domain-does-not-exist-12345.invalid",
			expectError: true,
			validateIP:  nil,
		},
		{
			name:        "Empty hostname",
			hostname:    "",
			expectError: true,
			validateIP:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ResolveHostname(tt.hostname)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if tt.validateIP != nil {
					tt.validateIP(t, ips)
				}
			}
		})
	}
}

// TestIpToUint32 tests IP string to uint32 conversion
func TestIpToUint32(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected uint32
	}{
		{
			name:     "Convert 127.0.0.1",
			ip:       "127.0.0.1",
			expected: 2130706433, // 0x7F000001
		},
		{
			name:     "Convert 192.168.1.1",
			ip:       "192.168.1.1",
			expected: 3232235777, // 0xC0A80101
		},
		{
			name:     "Convert 0.0.0.0",
			ip:       "0.0.0.0",
			expected: 0,
		},
		{
			name:     "Invalid IP",
			ip:       "invalid",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IpToUint32(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestUint32ToIp tests uint32 to IP string conversion
func TestUint32ToIp(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{
			name:     "Convert 2130706433",
			input:    2130706433,
			expected: "127.0.0.1",
		},
		{
			name:     "Convert 3232235777",
			input:    3232235777,
			expected: "192.168.1.1",
		},
		{
			name:     "Convert 0",
			input:    0,
			expected: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint32ToIp(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
