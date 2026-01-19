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

func TestGetRoles(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/roles", nil)
	w := httptest.NewRecorder()

	getRoles(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var roles []models.Role
	if err := json.NewDecoder(w.Body).Decode(&roles); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(roles) < 3 {
		t.Error("Expected at least 3 roles (admin, user, root) in response")
	}
}

func TestCreateRole(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name           string
		payload        models.Role
		expectedStatus int
	}{
		{
			name: "Successful role creation",
			payload: models.Role{
				Name:        "editor",
				Description: "Editor role",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Missing required name",
			payload: models.Role{
				Name:        "",
				Description: "Empty name role",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createRole(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated {
				var role models.Role
				if err := json.NewDecoder(w.Body).Decode(&role); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if role.Id == 0 {
					t.Error("Expected role ID to be set")
				}
			}
		})
	}
}

func TestCreateRoleDuplicate(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	payload := models.Role{
		Name:        "admin",
		Description: "Duplicate admin role",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	createRole(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate role, got %d", http.StatusConflict, w.Code)
	}
}

func TestDeleteRole(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	result, err := database.DB.Exec("INSERT INTO roles (name, description) VALUES (?, ?)",
		"deletable", "Deletable role")
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	roleID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		roleID         string
		expectedStatus int
	}{
		{
			name:           "Successful deletion",
			roleID:         "4",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Non-existent role",
			roleID:         "99999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid role ID",
			roleID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/roles/"+tt.roleID, nil)
			req.SetPathValue("id", tt.roleID)
			w := httptest.NewRecorder()

			deleteRole(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = roleID
}

func TestGetRoleServices(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"RoleService", "localhost:8080", "Role test service")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	createRoleServicesTable := `
		CREATE TABLE IF NOT EXISTS role_services (
			"role_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			PRIMARY KEY (role_id, service_id),
			FOREIGN KEY(role_id) REFERENCES roles(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createRoleServicesTable); err != nil {
		t.Fatalf("Failed to create role_services table: %v", err)
	}

	_, err = database.DB.Exec("INSERT INTO role_services (role_id, service_id) VALUES (1, 1)")
	if err != nil {
		t.Fatalf("Failed to link service to role: %v", err)
	}

	tests := []struct {
		name           string
		roleID         string
		expectedStatus int
	}{
		{
			name:           "Get services for role",
			roleID:         "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid role ID",
			roleID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/roles/"+tt.roleID+"/services", nil)
			req.SetPathValue("id", tt.roleID)
			w := httptest.NewRecorder()

			getRoleServices(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var services []models.Service
				if err := json.NewDecoder(w.Body).Decode(&services); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
			}
		})
	}
}

func TestAddRoleService(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"AddRoleService", "localhost:8080", "Add role service test")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	createRoleServicesTable := `
		CREATE TABLE IF NOT EXISTS role_services (
			"role_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			PRIMARY KEY (role_id, service_id),
			FOREIGN KEY(role_id) REFERENCES roles(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createRoleServicesTable); err != nil {
		t.Fatalf("Failed to create role_services table: %v", err)
	}

	tests := []struct {
		name           string
		roleID         string
		serviceID      int
		expectedStatus int
	}{
		{
			name:           "Successful service addition",
			roleID:         "1",
			serviceID:      1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid role ID",
			roleID:         "invalid",
			serviceID:      1,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]int{"service_id": tt.serviceID}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/roles/"+tt.roleID+"/services", bytes.NewReader(body))
			req.SetPathValue("id", tt.roleID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			addRoleService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestRemoveRoleService(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	_, err := database.DB.Exec("INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)",
		"RemoveRoleService", "localhost:8080", "Remove role service test")
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	createRoleServicesTable := `
		CREATE TABLE IF NOT EXISTS role_services (
			"role_id" INTEGER NOT NULL,
			"service_id" INTEGER NOT NULL,
			PRIMARY KEY (role_id, service_id),
			FOREIGN KEY(role_id) REFERENCES roles(id),
			FOREIGN KEY(service_id) REFERENCES services(id)
		);`
	if _, err := database.DB.Exec(createRoleServicesTable); err != nil {
		t.Fatalf("Failed to create role_services table: %v", err)
	}

	_, err = database.DB.Exec("INSERT INTO role_services (role_id, service_id) VALUES (1, 1)")
	if err != nil {
		t.Fatalf("Failed to link service to role: %v", err)
	}

	tests := []struct {
		name           string
		roleID         string
		serviceID      string
		expectedStatus int
	}{
		{
			name:           "Successful service removal",
			roleID:         "1",
			serviceID:      "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid role ID",
			roleID:         "invalid",
			serviceID:      "1",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid service ID",
			roleID:         "1",
			serviceID:      "invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/roles/"+tt.roleID+"/services/"+tt.serviceID, nil)
			req.SetPathValue("id", tt.roleID)
			req.SetPathValue("svc_id", tt.serviceID)
			w := httptest.NewRecorder()

			removeRoleService(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}
