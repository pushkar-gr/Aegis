package config

import (
	"flag"
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration values for the controller.
type Config struct {
	// Database settings
	DBDir  string
	DBPath string

	// Server settings
	ServerPort string
	CertFile   string
	KeyFile    string

	// gRPC Agent connection
	AgentAddress     string
	AgentCertFile    string
	AgentKeyFile     string
	AgentCAFile      string
	AgentServerName  string
	AgentCallTimeout time.Duration

	// Session monitoring
	MonitorRetryDelay time.Duration

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Authentication settings
	JwtKey           string
	JwtTokenLifetime time.Duration
}

// Load reads configuration from environment variables and command-line flags.
func Load() *Config {
	config := &Config{
		// Defaults
		DBDir:             getEnv("DB_DIR", "./data"),
		ServerPort:        getEnv("SERVER_PORT", ":443"),
		CertFile:          getEnv("CERT_FILE", "certs/server.crt"),
		KeyFile:           getEnv("KEY_FILE", "certs/server.key"),
		AgentAddress:      getEnv("AGENT_ADDRESS", "172.21.0.10:50001"),
		AgentCertFile:     getEnv("AGENT_CERT_FILE", "certs/controller.pem"),
		AgentKeyFile:      getEnv("AGENT_KEY_FILE", "certs/controller.key"),
		AgentCAFile:       getEnv("AGENT_CA_FILE", "certs/ca.pem"),
		AgentServerName:   getEnv("AGENT_SERVER_NAME", "aegis-agent"),
		AgentCallTimeout:  getDurationEnv("AGENT_CALL_TIMEOUT", time.Second),
		MonitorRetryDelay: getDurationEnv("MONITOR_RETRY_DELAY", 5*time.Second),
		MaxOpenConns:      getIntEnv("DB_MAX_OPEN_CONNS", 1),
		MaxIdleConns:      getIntEnv("DB_MAX_IDLE_CONNS", 1),
		ConnMaxLifetime:   getDurationEnv("DB_CONN_MAX_LIFETIME", time.Hour),
		JwtKey:            getEnv("JWT_SECRET", "DEFAULT_JWT_KEY"),
		JwtTokenLifetime:  getDurationEnv("JWT_TOKEN_LIFETIME", 60*time.Second),
	}

	if config.JwtKey == "DEFAULT_JWT_KEY" {
		log.Fatal("FATAL: JWT_SECRET environment variable is not found, using `DEFAULT_JWT_KEY`")
	}

	// Command-line flags override environment variables
	flag.StringVar(&config.ServerPort, "port", config.ServerPort, "Server port")
	flag.StringVar(&config.CertFile, "cert", config.CertFile, "Path to certificate file")
	flag.StringVar(&config.KeyFile, "key", config.KeyFile, "Path to key file")
	flag.StringVar(&config.AgentAddress, "agent-addr", config.AgentAddress, "Agent gRPC address")

	flag.Parse()

	return config
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getIntEnv retrieves an integer environment variable or returns a default value.
func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		log.Printf("[WARN] Invalid integer value for %s, using default: %d", key, defaultValue)
	}
	return defaultValue
}

// getDurationEnv retrieves a duration environment variable or returns a default value.
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		log.Printf("[WARN] Invalid duration value for %s, using default: %v", key, defaultValue)
	}
	return defaultValue
}
