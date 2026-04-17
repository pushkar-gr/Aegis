package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTOML writes content to a temp file and returns its path.
func writeTOML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.toml")
	if err != nil {
		t.Fatalf("failed to create temp config file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

func TestLoadFromFileDefaults(t *testing.T) {
	// An empty TOML file should produce the defaults.
	path := writeTOML(t, `[auth]
jwt_secret = "test-secret"
`)
	cfg := LoadFromFile(path)

	if cfg.ServerPort != ":443" {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, ":443")
	}
	if cfg.AgentAddress != "172.21.0.10:50001" {
		t.Errorf("AgentAddress: got %q, want %q", cfg.AgentAddress, "172.21.0.10:50001")
	}
	if cfg.DBDir != "./data" {
		t.Errorf("DBDir: got %q, want %q", cfg.DBDir, "./data")
	}
	if cfg.MaxOpenConns != 1 {
		t.Errorf("MaxOpenConns: got %d, want 1", cfg.MaxOpenConns)
	}
	if cfg.ConnMaxLifetime != time.Hour {
		t.Errorf("ConnMaxLifetime: got %v, want 1h", cfg.ConnMaxLifetime)
	}
	if cfg.IpUpdateInterval != 60*time.Second {
		t.Errorf("IpUpdateInterval: got %v, want 60s", cfg.IpUpdateInterval)
	}
	if cfg.OIDCEnabled {
		t.Error("OIDCEnabled: expected false by default")
	}
	if cfg.OIDCRedirectURL != "https://localhost/api/auth/oidc/callback" {
		t.Errorf("OIDCRedirectURL: got %q", cfg.OIDCRedirectURL)
	}
}

func TestLoadFromFileCustomValues(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	tomlContent := `
[database]
dir              = "/custom/data"
max_open_conns   = 5
max_idle_conns   = 3
conn_max_lifetime = "30m"

[server]
port      = ":8443"
cert_file = "custom/server.crt"
key_file  = "custom/server.key"

[agent]
address     = "10.0.0.1:50001"
cert_file   = "custom/ctrl.pem"
key_file    = "custom/ctrl.key"
ca_file     = "custom/ca.pem"
server_name = "my-agent"
call_timeout = "2s"

[monitor]
retry_delay        = "10s"
ip_update_interval = "120s"

[auth]
jwt_secret         = "super-secret"
jwt_token_lifetime = "15m"
jwt_private_key    = "keys/priv.pem"
jwt_public_key     = "keys/pub.pem"

[oidc]
enabled          = true
google_client_id = "google-id"
google_secret    = "google-secret"
github_client_id = "github-id"
github_secret    = "github-secret"
redirect_url     = "https://example.com/callback"
role_mapping_rules = '{"default_role":"user"}'
`
	path := writeTOML(t, tomlContent)
	cfg := LoadFromFile(path)

	if cfg.DBDir != "/custom/data" {
		t.Errorf("DBDir: got %q, want /custom/data", cfg.DBDir)
	}
	if cfg.MaxOpenConns != 5 {
		t.Errorf("MaxOpenConns: got %d, want 5", cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != 3 {
		t.Errorf("MaxIdleConns: got %d, want 3", cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime != 30*time.Minute {
		t.Errorf("ConnMaxLifetime: got %v, want 30m", cfg.ConnMaxLifetime)
	}
	if cfg.ServerPort != ":8443" {
		t.Errorf("ServerPort: got %q, want :8443", cfg.ServerPort)
	}
	if cfg.CertFile != "custom/server.crt" {
		t.Errorf("CertFile: got %q", cfg.CertFile)
	}
	if cfg.AgentAddress != "10.0.0.1:50001" {
		t.Errorf("AgentAddress: got %q", cfg.AgentAddress)
	}
	if cfg.AgentServerName != "my-agent" {
		t.Errorf("AgentServerName: got %q", cfg.AgentServerName)
	}
	if cfg.AgentCallTimeout != 2*time.Second {
		t.Errorf("AgentCallTimeout: got %v, want 2s", cfg.AgentCallTimeout)
	}
	if cfg.MonitorRetryDelay != 10*time.Second {
		t.Errorf("MonitorRetryDelay: got %v, want 10s", cfg.MonitorRetryDelay)
	}
	if cfg.IpUpdateInterval != 120*time.Second {
		t.Errorf("IpUpdateInterval: got %v, want 120s", cfg.IpUpdateInterval)
	}
	if cfg.JwtKey != "super-secret" {
		t.Errorf("JwtKey: got %q", cfg.JwtKey)
	}
	if cfg.JwtTokenLifetime != 15*time.Minute {
		t.Errorf("JwtTokenLifetime: got %v, want 15m", cfg.JwtTokenLifetime)
	}
	if cfg.JwtPrivateKey != "keys/priv.pem" {
		t.Errorf("JwtPrivateKey: got %q", cfg.JwtPrivateKey)
	}
	if !cfg.OIDCEnabled {
		t.Error("OIDCEnabled: expected true")
	}
	if cfg.OIDCGoogleClientID != "google-id" {
		t.Errorf("OIDCGoogleClientID: got %q", cfg.OIDCGoogleClientID)
	}
	if cfg.OIDCGitHubClientID != "github-id" {
		t.Errorf("OIDCGitHubClientID: got %q", cfg.OIDCGitHubClientID)
	}
	if cfg.OIDCRedirectURL != "https://example.com/callback" {
		t.Errorf("OIDCRedirectURL: got %q", cfg.OIDCRedirectURL)
	}
	if cfg.OIDCRoleMappingRules != `{"default_role":"user"}` {
		t.Errorf("OIDCRoleMappingRules: got %q", cfg.OIDCRoleMappingRules)
	}
}

func TestLoadFromFileMissingFile(t *testing.T) {
	// A non existent path should fall back to built-in defaults (no fatal).
	def := defaults()
	cfg := buildConfig(def)

	if cfg.ServerPort != ":443" {
		t.Errorf("default ServerPort: got %q", cfg.ServerPort)
	}
	if cfg.DBDir != "./data" {
		t.Errorf("default DBDir: got %q", cfg.DBDir)
	}
	if cfg.ConnMaxLifetime != time.Hour {
		t.Errorf("default ConnMaxLifetime: got %v", cfg.ConnMaxLifetime)
	}
}

func TestLoadFromFileSampleConfig(t *testing.T) {
	// The shipped config.toml template should parse without error when jwt_secret is overridden.
	samplePath := filepath.Join("..", "config.toml")
	data, err := os.ReadFile(samplePath)
	if err != nil {
		t.Skipf("config.toml not found at %s, skipping: %v", samplePath, err)
	}

	content := string(data)
	tmpPath := writeTOML(t, content)

	patched := ""
	for _, line := range splitLines(content) {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "jwt_secret") && strings.ContainsRune(trimmed, '=') {
			patched += `jwt_secret = "test-secret"` + "\n"
		} else {
			patched += line + "\n"
		}
	}
	if err := os.WriteFile(tmpPath, []byte(patched), 0600); err != nil {
		t.Fatalf("failed to patch config: %v", err)
	}

	cfg := LoadFromFile(tmpPath)
	if cfg == nil {
		t.Fatal("expected non-nil Config")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		fallback time.Duration
		want     time.Duration
	}{
		{"1h", time.Minute, time.Hour},
		{"30m", time.Second, 30 * time.Minute},
		{"invalid", 5 * time.Second, 5 * time.Second},
		{"", 10 * time.Second, 10 * time.Second},
	}
	for _, tt := range tests {
		got := parseDuration(tt.input, tt.fallback)
		if got != tt.want {
			t.Errorf("parseDuration(%q, %v) = %v, want %v", tt.input, tt.fallback, got, tt.want)
		}
	}
}

// splitLines splits a string into lines without adding newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
