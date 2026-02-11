package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetServices(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"TestService", "localhost:8080", 0x7F000001, 8080, "Test service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	w := httptest.NewRecorder()

	getServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var services []models.Service
	if err := json.NewDecoder(w.Body).Decode(&services); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(services) == 0 {
		t.Error("Expected at least one service in response")
	}
}

func TestCreateService(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name           string
		payload        models.Service
		expectedStatus int
	}{
		{
			name: "Successful service creation",
			payload: models.Service{
				Name:        "NewService",
				Hostname:    "localhost:9090",
				Description: "New test service",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Missing required fields",
			payload: models.Service{
				Name:     "",
				Hostname: "localhost:9090",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated {
				var service models.Service
				if err := json.NewDecoder(w.Body).Decode(&service); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if service.Id == 0 {
					t.Error("Expected service ID to be set")
				}
			}
		})
	}
}

func TestCreateServiceDuplicate(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"ExistingService", "localhost:8080", 0x7F000001, 8080, "Existing service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	payload := models.Service{
		Name:        "ExistingService",
		Hostname:    "localhost:8080",
		Description: "Duplicate service",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	createService(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate service, got %d", http.StatusConflict, w.Code)
	}
}

func TestUpdateService(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	result, err := database.DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"UpdateService", "localhost:8080", 0x7F000001, 8080, "Update test")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		serviceID      string
		payload        models.Service
		expectedStatus int
	}{
		{
			name:      "Successful update",
			serviceID: "1",
			payload: models.Service{
				Name:        "UpdatedService",
				Hostname:    "localhost:9090",
				Description: "Updated description",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "Invalid service ID",
			serviceID: "invalid",
			payload: models.Service{
				Name:     "UpdatedService",
				Hostname: "localhost:9090",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "Non-existent service",
			serviceID: "99999",
			payload: models.Service{
				Name:     "UpdatedService",
				Hostname: "localhost:9090",
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPut, "/api/services/"+tt.serviceID, bytes.NewReader(body))
			req.SetPathValue("id", tt.serviceID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			updateService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = serviceID
}

func TestDeleteService(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	result, err := database.DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"DeleteService", "localhost:8080", 0x7F000001, 8080, "Delete test")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		serviceID      string
		expectedStatus int
	}{
		{
			name:           "Successful deletion",
			serviceID:      "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Non-existent service",
			serviceID:      "99999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid service ID",
			serviceID:      "invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/services/"+tt.serviceID, nil)
			req.SetPathValue("id", tt.serviceID)
			w := httptest.NewRecorder()

			deleteService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = serviceID
}

// TestCreateServiceWithHostnameResolution tests hostname resolution during service creation
func TestCreateServiceWithHostnameResolution(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name           string
		payload        models.Service
		expectedStatus int
		validateFunc   func(t *testing.T, service models.Service)
	}{
		{
			name: "Valid hostname resolves to IP",
			payload: models.Service{
				Name:        "HostnameService",
				Hostname:    "localhost:8080",
				Description: "Service with hostname",
			},
			expectedStatus: http.StatusCreated,
			validateFunc: func(t *testing.T, service models.Service) {
				if service.Hostname != "localhost:8080" {
					t.Errorf("Expected hostname 'localhost:8080', got '%s'", service.Hostname)
				}
				if service.Ip != 0x7F000001 || service.Port != 8080 {
					t.Errorf("Expected ip 0x7F000001 port 8080, got ip 0x%08X port %d", service.Ip, service.Port)
				}
			},
		},
		{
			name: "IP address as hostname",
			payload: models.Service{
				Name:        "IPService",
				Hostname:    "192.168.1.1:9000",
				Description: "Service with IP",
			},
			expectedStatus: http.StatusCreated,
			validateFunc: func(t *testing.T, service models.Service) {
				if service.Hostname != "192.168.1.1:9000" {
					t.Errorf("Expected hostname '192.168.1.1:9000', got '%s'", service.Hostname)
				}
				if service.Ip != 0xC0A80101 || service.Port != 9000 {
					t.Errorf("Expected ip 0xC0A80101 port 9000, got ip 0x%08X port %d", service.Ip, service.Port)
				}
			},
		},
		{
			name: "Invalid hostname format - no port",
			payload: models.Service{
				Name:        "InvalidService",
				Hostname:    "localhost",
				Description: "Invalid format",
			},
			expectedStatus: http.StatusBadRequest,
			validateFunc:   nil,
		},
		{
			name: "Invalid hostname - non-existent domain",
			payload: models.Service{
				Name:        "NonExistentService",
				Hostname:    "this-domain-does-not-exist-12345.invalid:8080",
				Description: "Non-existent domain",
			},
			expectedStatus: http.StatusBadRequest,
			validateFunc:   nil,
		},
		{
			name: "Missing hostname field",
			payload: models.Service{
				Name:        "NoHostnameService",
				Description: "No hostname provided",
			},
			expectedStatus: http.StatusBadRequest,
			validateFunc:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated && tt.validateFunc != nil {
				var service models.Service
				if err := json.NewDecoder(w.Body).Decode(&service); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				tt.validateFunc(t, service)
			}
		})
	}
}

// TestUpdateServiceWithHostnameResolution tests hostname resolution during service update
func TestUpdateServiceWithHostnameResolution(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	// Create initial service
	result, err := database.DB.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		"UpdateHostnameTest", "localhost:8080", 0x7F000001, 8080, "Initial service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		payload        models.Service
		expectedStatus int
		validateFunc   func(t *testing.T, service models.Service)
	}{
		{
			name: "Update hostname successfully",
			payload: models.Service{
				Name:        "UpdatedHostnameService",
				Hostname:    "localhost:9090",
				Description: "Updated with new hostname",
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, service models.Service) {
				if service.Hostname != "localhost:9090" {
					t.Errorf("Expected hostname 'localhost:9090', got '%s'", service.Hostname)
				}
				if service.Ip != 0x7F000001 || service.Port != 9090 {
					t.Errorf("Expected ip 0x7F000001 port 9090, got ip 0x%08X port %d", service.Ip, service.Port)
				}
			},
		},
		{
			name: "Update with invalid hostname format",
			payload: models.Service{
				Name:        "UpdatedService",
				Hostname:    "invalid-format",
				Description: "Invalid update",
			},
			expectedStatus: http.StatusBadRequest,
			validateFunc:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPut, "/api/services/1", bytes.NewReader(body))
			req.SetPathValue("id", "1")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			updateService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusOK && tt.validateFunc != nil {
				var service models.Service
				if err := json.NewDecoder(w.Body).Decode(&service); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				tt.validateFunc(t, service)
			}
		})
	}

	_ = serviceID
}

// TestCreateServiceErrorMessages tests that error messages are descriptive
func TestCreateServiceErrorMessages(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name             string
		payload          models.Service
		expectedStatus   int
		expectedErrorMsg string
	}{
		{
			name: "Format error provides clear message",
			payload: models.Service{
				Name:        "InvalidFormatService",
				Hostname:    "no-port-here",
				Description: "Should fail with format error",
			},
			expectedStatus:   http.StatusBadRequest,
			expectedErrorMsg: "invalid hostname format",
		},
		{
			name: "DNS resolution error provides clear message",
			payload: models.Service{
				Name:        "DNSFailService",
				Hostname:    "nonexistent-domain-12345.invalid:8080",
				Description: "Should fail with DNS error",
			},
			expectedStatus:   http.StatusBadRequest,
			expectedErrorMsg: "DNS resolution failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			responseBody := w.Body.String()
			if !strings.Contains(responseBody, tt.expectedErrorMsg) {
				t.Errorf("Expected error message to contain '%s', got: %s", tt.expectedErrorMsg, responseBody)
			}
		})
	}
}

// TestIPAddressOptimization verifies that IP addresses don't trigger DNS lookups
func TestIPAddressOptimization(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		hostname   string
		expectedIp uint32
		expectedPort uint16
	}{
		{
			name:       "IPv4 address passes through",
			hostname:   "192.168.1.100:8080",
			expectedIp: 0xC0A80164, // 192.168.1.100
			expectedPort: 8080,
		},
		{
			name:       "Another IPv4 address",
			hostname:   "10.0.0.1:9000",
			expectedIp: 0x0A000001, // 10.0.0.1
			expectedPort: 9000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := models.Service{
				Name:        "IPTest" + tt.name,
				Hostname:    tt.hostname,
				Description: "Testing IP optimization",
			}

			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createService(w, req)

			if w.Code != http.StatusCreated {
				t.Errorf("Expected status %d, got %d. Response: %s", http.StatusCreated, w.Code, w.Body.String())
			}

			var service models.Service
			if err := json.NewDecoder(w.Body).Decode(&service); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if service.Ip != tt.expectedIp || service.Port != tt.expectedPort {
				t.Errorf("Expected ip 0x%08X port %d, got ip 0x%08X port %d", 
					tt.expectedIp, tt.expectedPort, service.Ip, service.Port)
			}
		})
	}
}
