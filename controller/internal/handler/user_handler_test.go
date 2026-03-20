package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetUsers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	if _, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "user1", hashedPassword); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.GET("/api/users", h.GetAll)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var users []models.User
	if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(users) == 0 {
		t.Error("Expected at least one user in response")
	}
}

func TestCreateUser(t *testing.T) {
	userRepo, _, _, cleanup := setupTestRepos(t)
	defer cleanup()

	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.POST("/api/users", h.Create)

	tests := []struct {
		name           string
		payload        models.UserWithCredentials
		expectedStatus int
	}{
		{
			name: "Successful user creation",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{Username: "newuser", Password: "ValidPass123!"},
				RoleId:      2,
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Invalid username format",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{Username: "ab", Password: "ValidPass123!"},
				RoleId:      2,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Weak password",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{Username: "validuser", Password: "weak"},
				RoleId:      2,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing role_id",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{Username: "validuser2", Password: "ValidPass123!"},
				RoleId:      0,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated {
				var user models.UserWithCredentials
				if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if user.Id == 0 {
					t.Error("Expected user ID to be set")
				}
			}
		})
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	if _, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "existinguser", hashedPassword); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.POST("/api/users", h.Create)

	payload := models.UserWithCredentials{
		Credentials: models.Credentials{Username: "existinguser", Password: "ValidPass123!"},
		RoleId:      2,
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate user, got %d", http.StatusConflict, w.Code)
	}
}

func TestDeleteUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "deleteuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.DELETE("/api/users/:id", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "adminuser")
	}, h.Delete)

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{"Successful deletion", fmt.Sprintf("%d", userID), http.StatusOK},
		{"Non-existent user", "99999", http.StatusNotFound},
		{"Invalid user ID", "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/users/"+tt.userID, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestUpdateUserRole(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "roleuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.PUT("/api/users/:id/role", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "adminuser")
	}, h.UpdateRole)

	tests := []struct {
		name           string
		userID         string
		newRoleID      int
		expectedStatus int
	}{
		{"Successful role update", fmt.Sprintf("%d", userID), 1, http.StatusOK},
		{"Invalid user ID", "invalid", 1, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]int{"role_id": tt.newRoleID}
			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/api/users/"+tt.userID+"/role", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetUserServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	userResult, _ := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "svcuser", hashedPassword)
	userID, _ := userResult.LastInsertId()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)", "UserSvc", "localhost:8080", 0x7F000001, 8080, "User service")
	svcID, _ := svcResult.LastInsertId()

	if _, err := db.Exec("INSERT INTO user_extra_services (user_id, service_id) VALUES (?, ?)", userID, svcID); err != nil {
		t.Fatalf("Failed to assign service to user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.GET("/api/users/:id/services", h.GetServices)

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{"Get services for user", fmt.Sprintf("%d", userID), http.StatusOK},
		{"Invalid user ID", "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/users/"+tt.userID+"/services", nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestAddUserService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	userResult, _ := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "addsvcuser", hashedPassword)
	userID, _ := userResult.LastInsertId()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)", "AddSvc", "localhost:8080", 0x7F000001, 8080, "Add service")
	svcID, _ := svcResult.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.POST("/api/users/:id/services", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "adminuser")
	}, h.AddService)

	tests := []struct {
		name           string
		userID         string
		serviceID      int
		expectedStatus int
	}{
		{"Successful service addition", fmt.Sprintf("%d", userID), int(svcID), http.StatusOK},
		{"Invalid user ID", "invalid", int(svcID), http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]int{"service_id": tt.serviceID}
			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/users/"+tt.userID+"/services", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestRemoveUserService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	userResult, _ := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "remsvcuser", hashedPassword)
	userID, _ := userResult.LastInsertId()

	svcResult, _ := db.Exec("INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)", "RemSvc", "localhost:8080", 0x7F000001, 8080, "Remove service")
	svcID, _ := svcResult.LastInsertId()

	if _, err := db.Exec("INSERT INTO user_extra_services (user_id, service_id) VALUES (?, ?)", userID, svcID); err != nil {
		t.Fatalf("Failed to link service to user: %v", err)
	}

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.DELETE("/api/users/:id/services/:svc_id", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "adminuser")
	}, h.RemoveService)

	tests := []struct {
		name           string
		userID         string
		serviceID      string
		expectedStatus int
	}{
		{"Successful service removal", fmt.Sprintf("%d", userID), fmt.Sprintf("%d", svcID), http.StatusOK},
		{"Invalid user ID", "invalid", fmt.Sprintf("%d", svcID), http.StatusBadRequest},
		{"Invalid service ID", fmt.Sprintf("%d", userID), "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/users/"+tt.userID+"/services/"+tt.serviceID, nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestResetUserPassword(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := db.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)", "resetuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	userRepo, _ := createReposFromDB(t, db)
	userSvc := service.NewUserService(userRepo)
	h := NewUserHandler(userSvc)

	r := gin.New()
	r.POST("/api/users/:id/reset-password", func(c *gin.Context) {
		c.Set(middleware.UsernameKey, "adminuser")
	}, h.ResetPassword)

	tests := []struct {
		name           string
		userID         string
		newPassword    string
		expectedStatus int
	}{
		{"Successful password reset", fmt.Sprintf("%d", userID), "NewValidPass123!", http.StatusOK},
		{"Weak password", fmt.Sprintf("%d", userID), "weak", http.StatusBadRequest},
		{"Invalid user ID", "invalid", "NewValidPass123!", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{"password": tt.newPassword}
			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/users/"+tt.userID+"/reset-password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}
