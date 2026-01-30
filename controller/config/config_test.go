package config

import (
	"os"
	"testing"
	"time"
)

func TestGetEnv(t *testing.T) {
	os.Clearenv()

	// Test with default value
	val := getEnv("TEST_STRING", "default")
	if val != "default" {
		t.Errorf("Expected 'default', got %s", val)
	}

	// Test with environment variable
	_ = os.Setenv("TEST_STRING", "custom")
	val = getEnv("TEST_STRING", "default")
	if val != "custom" {
		t.Errorf("Expected 'custom', got %s", val)
	}
}

func TestGetIntEnv(t *testing.T) {
	os.Clearenv()

	// Test with default value
	val := getIntEnv("TEST_INT", 42)
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}

	// Test with valid environment variable
	_ = os.Setenv("TEST_INT", "100")
	val = getIntEnv("TEST_INT", 42)
	if val != 100 {
		t.Errorf("Expected 100, got %d", val)
	}

	// Test with invalid environment variable (should use default)
	_ = os.Setenv("TEST_INT", "invalid")
	val = getIntEnv("TEST_INT", 42)
	if val != 42 {
		t.Errorf("Expected 42 for invalid int, got %d", val)
	}
}

func TestGetDurationEnv(t *testing.T) {
	os.Clearenv()

	// Test with default value
	val := getDurationEnv("TEST_DURATION", 5*time.Second)
	if val != 5*time.Second {
		t.Errorf("Expected 5s, got %v", val)
	}

	// Test with valid environment variable
	_ = os.Setenv("TEST_DURATION", "10s")
	val = getDurationEnv("TEST_DURATION", 5*time.Second)
	if val != 10*time.Second {
		t.Errorf("Expected 10s, got %v", val)
	}

	// Test with invalid environment variable (should use default)
	_ = os.Setenv("TEST_DURATION", "invalid")
	val = getDurationEnv("TEST_DURATION", 5*time.Second)
	if val != 5*time.Second {
		t.Errorf("Expected 5s for invalid duration, got %v", val)
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test that defaults are reasonable (without calling Load which uses flags)
	os.Clearenv()

	dbDir := getEnv("DB_DIR", "./data")
	if dbDir != "./data" {
		t.Errorf("Expected DBDir './data', got %s", dbDir)
	}

	serverPort := getEnv("SERVER_PORT", ":443")
	if serverPort != ":443" {
		t.Errorf("Expected ServerPort ':443', got %s", serverPort)
	}

	agentAddr := getEnv("AGENT_ADDRESS", "172.21.0.10:50001")
	if agentAddr != "172.21.0.10:50001" {
		t.Errorf("Expected AgentAddress '172.21.0.10:50001', got %s", agentAddr)
	}
}

func TestConfigFromEnv(t *testing.T) {
	// Test that environment variables are read correctly
	os.Clearenv()
	_ = os.Setenv("DB_DIR", "/custom/data")
	_ = os.Setenv("SERVER_PORT", ":8443")
	_ = os.Setenv("AGENT_ADDRESS", "10.0.0.1:50002")

	dbDir := getEnv("DB_DIR", "./data")
	if dbDir != "/custom/data" {
		t.Errorf("Expected DBDir '/custom/data', got %s", dbDir)
	}

	serverPort := getEnv("SERVER_PORT", ":443")
	if serverPort != ":8443" {
		t.Errorf("Expected ServerPort ':8443', got %s", serverPort)
	}

	agentAddr := getEnv("AGENT_ADDRESS", "172.21.0.10:50001")
	if agentAddr != "10.0.0.1:50002" {
		t.Errorf("Expected AgentAddress '10.0.0.1:50002', got %s", agentAddr)
	}

	os.Clearenv()
}
