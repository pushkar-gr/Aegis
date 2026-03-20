package handler

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/service"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetRoles(t *testing.T) {
	_, _, roleRepo, cleanup := setupTestRepos(t)
	defer cleanup()

	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.GET("/api/roles", h.GetAll)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/roles", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var roles []models.Role
	if err := json.NewDecoder(w.Body).Decode(&roles); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(roles) == 0 {
		t.Error("Expected at least one role in response")
	}
}

func TestCreateRole(t *testing.T) {
	_, _, roleRepo, cleanup := setupTestRepos(t)
	defer cleanup()

	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.POST("/api/roles", h.Create)

	tests := []struct {
		name           string
		payload        models.Role
		expectedStatus int
	}{
		{"Successful role creation", models.Role{Name: "editor", Description: "Editor"}, http.StatusCreated},
		{"Missing role name", models.Role{Description: "No name"}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateRoleDuplicate(t *testing.T) {
	_, _, roleRepo, cleanup := setupTestRepos(t)
	defer cleanup()

	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.POST("/api/roles", h.Create)

	// "admin" already exists from seed
	body, _ := json.Marshal(models.Role{Name: "admin", Description: "Duplicate"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate role, got %d", http.StatusConflict, w.Code)
	}
}

func TestDeleteRole(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	result, err := db.Exec("INSERT INTO roles (name, description) VALUES (?, ?)", "tobedeleted", "Delete me")
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	roleID, _ := result.LastInsertId()

	_, roleRepo := createReposFromDB(t, db)
	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.DELETE("/api/roles/:id", h.Delete)

	tests := []struct {
		name           string
		roleID         string
		expectedStatus int
	}{
		{"Successful deletion", fmt.Sprintf("%d", roleID), http.StatusOK},
		{"Non-existent role", "99999", http.StatusNotFound},
		{"Invalid role ID", "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/roles/"+tt.roleID, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetRoleServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "RoleSvc", "localhost:8080", 0x7F000001, 8080)
	svcID, _ := svcResult.LastInsertId()

	var roleID int64 = 1 // admin
	if _, err := db.Exec("INSERT INTO role_services (role_id, service_id) VALUES (?, ?)", roleID, svcID); err != nil {
		t.Fatalf("Failed to link service to role: %v", err)
	}

	_, roleRepo := createReposFromDB(t, db)
	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.GET("/api/roles/:id/services", h.GetServices)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/roles/%d/services", roleID), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestAddRoleService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "RSvc", "localhost:8080", 0x7F000001, 8080)
	svcID, _ := svcResult.LastInsertId()

	_, roleRepo := createReposFromDB(t, db)
	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.POST("/api/roles/:id/services", h.AddService)

	payload := map[string]int{"service_id": int(svcID)}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/roles/1/services", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestRemoveRoleService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "RemRSvc", "localhost:8080", 0x7F000001, 8080)
	svcID, _ := svcResult.LastInsertId()
	var roleID int64 = 1
	if _, err := db.Exec("INSERT OR IGNORE INTO role_services (role_id, service_id) VALUES (?, ?)", roleID, svcID); err != nil {
		t.Fatalf("Failed to link service to role: %v", err)
	}

	_, roleRepo := createReposFromDB(t, db)
	roleSvc := service.NewRoleService(roleRepo)
	h := NewRoleHandler(roleSvc)

	r := gin.New()
	r.DELETE("/api/roles/:id/services/:svc_id", h.RemoveService)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/roles/%d/services/%d", roleID, svcID), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}
}
