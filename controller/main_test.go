package main

import (
	"Aegis/controller/internal/utils"
	"database/sql"
	"fmt"
	"net"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	// Create schema
	schema := `
		CREATE TABLE services (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			hostname TEXT NOT NULL,
			ip INTEGER NOT NULL,
			port INTEGER NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

func TestIPPortParsing(t *testing.T) {
	tests := []struct {
		name     string
		ipPort   string
		wantErr  bool
		wantHost string
		wantPort string
	}{
		{
			name:     "valid IPv4 with port",
			ipPort:   "10.0.0.1:80",
			wantErr:  false,
			wantHost: "10.0.0.1",
			wantPort: "80",
		},
		{
			name:     "valid IPv4 with high port",
			ipPort:   "192.168.1.1:8080",
			wantErr:  false,
			wantHost: "192.168.1.1",
			wantPort: "8080",
		},
		{
			name:    "invalid format - no port",
			ipPort:  "10.0.0.1",
			wantErr: true,
		},
		{
			name:    "invalid format - empty",
			ipPort:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := net.SplitHostPort(tt.ipPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if host != tt.wantHost {
					t.Errorf("host = %v, want %v", host, tt.wantHost)
				}
				if port != tt.wantPort {
					t.Errorf("port = %v, want %v", port, tt.wantPort)
				}
			}
		})
	}
}

func TestIPConversion(t *testing.T) {
	tests := []struct {
		name   string
		ipStr  string
		wantIP uint32
	}{
		{
			name:   "10.0.0.1",
			ipStr:  "10.0.0.1",
			wantIP: 0x0A000001,
		},
		{
			name:   "192.168.1.1",
			ipStr:  "192.168.1.1",
			wantIP: 0xC0A80101,
		},
		{
			name:   "127.0.0.1",
			ipStr:  "127.0.0.1",
			wantIP: 0x7F000001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.IpToUint32(tt.ipStr)
			if got != tt.wantIP {
				t.Errorf("IpToUint32(%s) = 0x%08X, want 0x%08X", tt.ipStr, got, tt.wantIP)
			}

			// Test round-trip conversion
			gotStr := utils.Uint32ToIp(got)
			if gotStr != tt.ipStr {
				t.Errorf("Uint32ToIp(0x%08X) = %s, want %s", got, gotStr, tt.ipStr)
			}
		})
	}
}

func TestServiceMapCreation(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	// Insert test services
	services := []struct {
		name     string
		hostname string
		ip       uint32
		port     uint16
	}{
		{"service1", "example.com:80", 0x0A000001, 80},
		{"service2", "test.com:443", 0x0A000002, 443},
		{"service3", "api.test.com:8080", 0x0A000003, 8080},
	}

	for _, svc := range services {
		_, err := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)",
			svc.name, svc.hostname, svc.ip, svc.port)
		if err != nil {
			t.Fatalf("failed to insert service: %v", err)
		}
	}

	// Query services
	rows, err := db.Query("SELECT id, ip, port FROM services")
	if err != nil {
		t.Fatalf("failed to query services: %v", err)
	}
	defer func() { _ = rows.Close() }()

	serviceMap := make(map[string]int)
	for rows.Next() {
		var id int
		var ip uint32
		var port uint16
		if err := rows.Scan(&id, &ip, &port); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		// Format as "ip:port" string
		ipStr := utils.Uint32ToIp(ip)
		key := fmt.Sprintf("%s:%d", ipStr, port)
		serviceMap[key] = id
	}

	// Verify map
	if len(serviceMap) != len(services) {
		t.Errorf("expected %d services, got %d", len(services), len(serviceMap))
	}

	// Verify each service can be found
	for _, svc := range services {
		ipStr := utils.Uint32ToIp(svc.ip)
		key := fmt.Sprintf("%s:%d", ipStr, svc.port)
		if _, exists := serviceMap[key]; !exists {
			t.Errorf("service %s with key %s not found in map", svc.name, key)
		}
	}
}

func TestHostnameToParts(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "domain with port",
			hostname: "example.com:80",
			wantHost: "example.com",
			wantPort: "80",
			wantErr:  false,
		},
		{
			name:     "subdomain with port",
			hostname: "api.example.com:8080",
			wantHost: "api.example.com",
			wantPort: "8080",
			wantErr:  false,
		},
		{
			name:     "IP with port",
			hostname: "10.0.0.1:80",
			wantHost: "10.0.0.1",
			wantPort: "80",
			wantErr:  false,
		},
		{
			name:     "invalid - no port",
			hostname: "example.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := net.SplitHostPort(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if host != tt.wantHost {
					t.Errorf("host = %v, want %v", host, tt.wantHost)
				}
				if port != tt.wantPort {
					t.Errorf("port = %v, want %v", port, tt.wantPort)
				}
			}
		})
	}
}
