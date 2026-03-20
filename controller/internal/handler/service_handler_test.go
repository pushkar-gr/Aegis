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

func TestGetServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	if _, err := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "SvcA", "localhost:8080", 0x7F000001, 8080); err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, err := createServiceRepo(t, db)
	if err != nil {
		t.Fatalf("Failed to create service repo: %v", err)
	}

	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.GET("/api/services", h.GetAll)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var services []models.Service
	if err := json.NewDecoder(w.Body).Decode(&services); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(services) == 0 {
		t.Error("Expected at least one service")
	}
}

func TestDeleteService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	result, err := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "DelSvc", "localhost:9090", 0x7F000001, 9090)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	svcID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.DELETE("/api/services/:id", h.Delete)

	tests := []struct {
		name           string
		id             string
		expectedStatus int
	}{
		{"Successful deletion", fmt.Sprintf("%d", svcID), http.StatusOK},
		{"Non-existent service", "99999", http.StatusNotFound},
		{"Invalid ID", "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/services/"+tt.id, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.POST("/api/services", h.Create)

	tests := []struct {
		name           string
		payload        models.Service
		expectedStatus int
	}{
		{
			name:           "Missing hostname",
			payload:        models.Service{Name: "Test"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid hostname format",
			payload:        models.Service{Name: "Test", Hostname: "invalid-no-port"},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestUpdateService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.PUT("/api/services/:id", h.Update)

	tests := []struct {
		name           string
		id             string
		payload        models.Service
		expectedStatus int
	}{
		{
			name:           "Invalid service ID",
			id:             "invalid",
			payload:        models.Service{Name: "Test", Hostname: "localhost:8080"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Non-existent service",
			id:             "99999",
			payload:        models.Service{Name: "Test", Hostname: "127.0.0.1:8080"},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/api/services/"+tt.id, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}
