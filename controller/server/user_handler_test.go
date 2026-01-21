package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUsers(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"user1", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	w := httptest.NewRecorder()

	getUsers(w, req)

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
	cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name           string
		payload        models.UserWithCredentials
		expectedStatus int
	}{
		{
			name: "Successful user creation",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{
					Username: "newuser",
					Password: "ValidPass123!",
				},
				RoleId: 2,
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Invalid username format",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{
					Username: "ab",
					Password: "ValidPass123!",
				},
				RoleId: 2,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Weak password",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{
					Username: "validuser",
					Password: "weak",
				},
				RoleId: 2,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing role_id",
			payload: models.UserWithCredentials{
				Credentials: models.Credentials{
					Username: "validuser2",
					Password: "ValidPass123!",
				},
				RoleId: 0,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createUser(w, req)

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
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	_, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"existinguser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	payload := models.UserWithCredentials{
		Credentials: models.Credentials{
			Username: "existinguser",
			Password: "ValidPass123!",
		},
		RoleId: 2,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	createUser(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d for duplicate user, got %d", http.StatusConflict, w.Code)
	}
}

func TestDeleteUser(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"deleteuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{
			name:           "Successful deletion",
			userID:         "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Non-existent user",
			userID:         "99999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid user ID",
			userID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			w := httptest.NewRecorder()

			deleteUser(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = userID
}

func TestUpdateUserRole(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"roleuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		userID         string
		newRoleID      int
		expectedStatus int
	}{
		{
			name:           "Successful role update",
			userID:         "1",
			newRoleID:      1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid user ID",
			userID:         "invalid",
			newRoleID:      1,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]int{"role_id": tt.newRoleID}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPut, "/api/users/"+tt.userID+"/role", bytes.NewReader(body))
			req.SetPathValue("id", tt.userID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			updateUserRole(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = userID
}

func TestResetUserPassword(t *testing.T) {
	cleanup := setupTestServer(t)
	defer cleanup()

	hashedPassword, _ := utils.HashPassword("TestPass123!")
	result, err := database.DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, 2, 1)",
		"resetuser", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		userID         string
		newPassword    string
		expectedStatus int
	}{
		{
			name:           "Successful password reset",
			userID:         "1",
			newPassword:    "NewValidPass123!",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Weak password",
			userID:         "1",
			newPassword:    "weak",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid user ID",
			userID:         "invalid",
			newPassword:    "NewValidPass123!",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{"password": tt.newPassword}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/users/"+tt.userID+"/reset-password", bytes.NewReader(body))
			req.SetPathValue("id", tt.userID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			resetUserPassword(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}

	_ = userID
}
