package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetServices(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"TestService", "localhost:8080", "Test service")
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
				IpPort:      "localhost:9090",
				Description: "New test service",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Missing required fields",
			payload: models.Service{
				Name:   "",
				IpPort: "localhost:9090",
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

	_, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"ExistingService", "localhost:8080", "Existing service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	payload := models.Service{
		Name:        "ExistingService",
		IpPort:      "localhost:8080",
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

	result, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"UpdateService", "localhost:8080", "Update test")
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
				IpPort:      "localhost:9090",
				Description: "Updated description",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "Invalid service ID",
			serviceID: "invalid",
			payload: models.Service{
				Name:   "UpdatedService",
				IpPort: "localhost:9090",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "Non-existent service",
			serviceID: "99999",
			payload: models.Service{
				Name:   "UpdatedService",
				IpPort: "localhost:9090",
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

	result, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"DeleteService", "localhost:8080", "Delete test")
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
