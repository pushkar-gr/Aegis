package handler

import (
	"Aegis/controller/internal/middleware"
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

func TestCreateServiceSuccess(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.POST("/api/services", h.Create)

	payload := models.Service{Name: "NewService", Hostname: "127.0.0.1:9090", Description: "Test service"}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var created models.Service
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if created.Id == 0 {
		t.Error("Expected non-zero service ID in response")
	}
	if created.Name != payload.Name {
		t.Errorf("Expected service name %q, got %q", payload.Name, created.Name)
	}
}

func TestUpdateServiceSuccess(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	result, err := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "OrigSvc", "localhost:7070", 0x7F000001, 7070)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	svcID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.PUT("/api/services/:id", h.Update)

	payload := models.Service{Name: "UpdatedSvc", Hostname: "127.0.0.1:7071", Description: "updated"}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/services/%d", svcID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var updated models.Service
	if err := json.NewDecoder(w.Body).Decode(&updated); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if updated.Name != payload.Name {
		t.Errorf("Expected updated name %q, got %q", payload.Name, updated.Name)
	}
}

func TestGetMyServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "dashuser", "hashed")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.GET("/api/dashboard/services", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "dashuser")
	}, h.GetMyServices)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/services", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var svcs []models.Service
	if err := json.NewDecoder(w.Body).Decode(&svcs); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
}

func TestGetMyServicesUnknownUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.GET("/api/dashboard/services", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "ghost")
	}, h.GetMyServices)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/services", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for unknown user, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestGetMyActiveServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "activeuser", "hashed")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.GET("/api/dashboard/active", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "activeuser")
	}, h.GetMyActiveServices)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/active", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestSelectActiveServiceInvalidBody(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "seluser", "hashed")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.POST("/api/dashboard/activate", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "seluser")
	}, h.SelectActiveService)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/activate", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid body, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestSelectActiveServiceForbidden(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "forbiddenuser", "hashed")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port) VALUES (?, ?, ?, ?)", "ForbSvc", "localhost:6060", 0x7F000001, 6060)
	svcID, _ := svcResult.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.POST("/api/dashboard/activate", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "forbiddenuser")
	}, h.SelectActiveService)

	body, _ := json.Marshal(map[string]int{"service_id": int(svcID)})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/activate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for forbidden service, got %d. Response: %s", http.StatusForbidden, w.Code, w.Body.String())
	}
}

func TestDeselectActiveServiceInvalidID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "deseluser", "hashed")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	svcRepo, _ := createServiceRepo(t, db)
	svcSvc := service.NewServiceService(svcRepo)
	h := NewServiceHandler(svcSvc, userRepo)

	r := gin.New()
	r.DELETE("/api/dashboard/active/:svc_id", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "deseluser")
	}, h.DeselectActiveService)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/dashboard/active/invalid", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid service ID, got %d", http.StatusBadRequest, w.Code)
	}
}
