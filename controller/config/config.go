package config

import (
	"log"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultConfigPath is the default location for the TOML config file.
const DefaultConfigPath = "config.toml"

// Config holds all config values for the controller.
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
	IpUpdateInterval  time.Duration

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Authentication settings
	JwtKey           string
	JwtTokenLifetime time.Duration
	JwtPrivateKey    string
	JwtPublicKey     string

	// OIDC settings
	OIDCEnabled          bool
	OIDCGoogleClientID   string
	OIDCGoogleSecret     string
	OIDCGitHubClientID   string
	OIDCGitHubSecret     string
	OIDCRedirectURL      string
	OIDCRoleMappingRules string
}

// [database] section of config.toml.
type tomlDatabase struct {
	Dir             string `toml:"dir"`
	MaxOpenConns    int    `toml:"max_open_conns"`
	MaxIdleConns    int    `toml:"max_idle_conns"`
	ConnMaxLifetime string `toml:"conn_max_lifetime"`
}

// [server] section of config.toml.
type tomlServer struct {
	Port     string `toml:"port"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// [agent] section of config.toml.
type tomlAgent struct {
	Address     string `toml:"address"`
	CertFile    string `toml:"cert_file"`
	KeyFile     string `toml:"key_file"`
	CAFile      string `toml:"ca_file"`
	ServerName  string `toml:"server_name"`
	CallTimeout string `toml:"call_timeout"`
}

// [monitor] section of config.toml.
type tomlMonitor struct {
	RetryDelay       string `toml:"retry_delay"`
	IpUpdateInterval string `toml:"ip_update_interval"`
}

// [auth] section of config.toml.
type tomlAuth struct {
	JwtSecret        string `toml:"jwt_secret"`
	JwtTokenLifetime string `toml:"jwt_token_lifetime"`
	JwtPrivateKey    string `toml:"jwt_private_key"`
	JwtPublicKey     string `toml:"jwt_public_key"`
}

// [oidc] section of config.toml.
type tomlOIDC struct {
	Enabled          bool   `toml:"enabled"`
	GoogleClientID   string `toml:"google_client_id"`
	GoogleSecret     string `toml:"google_secret"`
	GitHubClientID   string `toml:"github_client_id"`
	GitHubSecret     string `toml:"github_secret"`
	RedirectURL      string `toml:"redirect_url"`
	RoleMappingRules string `toml:"role_mapping_rules"`
}

// TOML structure.
type tomlFile struct {
	Database tomlDatabase `toml:"database"`
	Server   tomlServer   `toml:"server"`
	Agent    tomlAgent    `toml:"agent"`
	Monitor  tomlMonitor  `toml:"monitor"`
	Auth     tomlAuth     `toml:"auth"`
	OIDC     tomlOIDC     `toml:"oidc"`
}

// defaults returns the default tomlFile values.
func defaults() tomlFile {
	return tomlFile{
		Database: tomlDatabase{
			Dir:             "./data",
			MaxOpenConns:    1,
			MaxIdleConns:    1,
			ConnMaxLifetime: "1h",
		},
		Server: tomlServer{
			Port:     ":443",
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
		Agent: tomlAgent{
			Address:     "172.21.0.10:50001",
			CertFile:    "certs/controller.pem",
			KeyFile:     "certs/controller.key",
			CAFile:      "certs/ca.pem",
			ServerName:  "aegis-agent",
			CallTimeout: "1s",
		},
		Monitor: tomlMonitor{
			RetryDelay:       "5s",
			IpUpdateInterval: "60s",
		},
		Auth: tomlAuth{
			JwtSecret:        "CHANGE_ME",
			JwtTokenLifetime: "60s",
			JwtPrivateKey:    "keys/jwt_private.pem",
			JwtPublicKey:     "keys/jwt_public.pem",
		},
		OIDC: tomlOIDC{
			Enabled:          false,
			RedirectURL:      "https://localhost/api/auth/oidc/callback",
			RoleMappingRules: `{"domain_mappings":{"@company.com":"user","admin@company.com":"admin"}}`,
		},
	}
}

// Fallback durations for each field.
var defaultDurations = struct {
	ConnMaxLifetime   time.Duration
	AgentCallTimeout  time.Duration
	MonitorRetryDelay time.Duration
	IpUpdateInterval  time.Duration
	JwtTokenLifetime  time.Duration
}{
	ConnMaxLifetime:   time.Hour,
	AgentCallTimeout:  time.Second,
	MonitorRetryDelay: 5 * time.Second,
	IpUpdateInterval:  60 * time.Second,
	JwtTokenLifetime:  60 * time.Second,
}

// parseDuration parses a duration string. If invalide returns fallback duration.
func parseDuration(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	log.Printf("[WARN] Invalid duration %q, using default: %v", s, fallback)
	return fallback
}

// returns Config struct from toml.
func buildConfig(tf tomlFile) *Config {
	cfg := &Config{
		DBDir:                tf.Database.Dir,
		MaxOpenConns:         tf.Database.MaxOpenConns,
		MaxIdleConns:         tf.Database.MaxIdleConns,
		ConnMaxLifetime:      parseDuration(tf.Database.ConnMaxLifetime, defaultDurations.ConnMaxLifetime),
		ServerPort:           tf.Server.Port,
		CertFile:             tf.Server.CertFile,
		KeyFile:              tf.Server.KeyFile,
		AgentAddress:         tf.Agent.Address,
		AgentCertFile:        tf.Agent.CertFile,
		AgentKeyFile:         tf.Agent.KeyFile,
		AgentCAFile:          tf.Agent.CAFile,
		AgentServerName:      tf.Agent.ServerName,
		AgentCallTimeout:     parseDuration(tf.Agent.CallTimeout, defaultDurations.AgentCallTimeout),
		MonitorRetryDelay:    parseDuration(tf.Monitor.RetryDelay, defaultDurations.MonitorRetryDelay),
		IpUpdateInterval:     parseDuration(tf.Monitor.IpUpdateInterval, defaultDurations.IpUpdateInterval),
		JwtKey:               tf.Auth.JwtSecret,
		JwtTokenLifetime:     parseDuration(tf.Auth.JwtTokenLifetime, defaultDurations.JwtTokenLifetime),
		JwtPrivateKey:        tf.Auth.JwtPrivateKey,
		JwtPublicKey:         tf.Auth.JwtPublicKey,
		OIDCEnabled:          tf.OIDC.Enabled,
		OIDCGoogleClientID:   tf.OIDC.GoogleClientID,
		OIDCGoogleSecret:     tf.OIDC.GoogleSecret,
		OIDCGitHubClientID:   tf.OIDC.GitHubClientID,
		OIDCGitHubSecret:     tf.OIDC.GitHubSecret,
		OIDCRedirectURL:      tf.OIDC.RedirectURL,
		OIDCRoleMappingRules: tf.OIDC.RoleMappingRules,
	}
	return cfg
}

// Load reads config from the default TOML file. returns default if file not found.
func Load() *Config {
	return LoadFromFile(DefaultConfigPath)
}

// LoadFromFile reads config from given file. returns default if file not found.
func LoadFromFile(path string) *Config {
	tf := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("[FATAL] Failed to read config file %s: %v", path, err)
		}
		log.Printf("[WARN] Config file %s not found, using built-in defaults", path)
	} else {
		if err := toml.Unmarshal(data, &tf); err != nil {
			log.Fatalf("[FATAL] Failed to parse config file %s: %v", path, err)
		}
	}

	cfg := buildConfig(tf)

	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JwtKey = jwtSecret
	}

	if cfg.JwtKey == "CHANGE_ME" {
		log.Fatal("[FATAL] auth.jwt_secret in config.toml must be changed from the default placeholder value")
	}

	return cfg
}
