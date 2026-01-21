package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

var UsernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")

// getUsers retrieves all users from the database.
// Response: 200 OK with user list | 500 Internal Server Error
func getUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := database.DB.Query("SELECT id, username, role_id, is_active FROM users")
	if err != nil {
		log.Printf("[users] get all failed: database query error - %v", err)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[users] failed to close rows: %v", err)
		}
	}()

	users := make([]models.User, 0, 10)
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.Id, &u.Username, &u.RoleId, &u.IsActive); err != nil {
			log.Printf("[users] get all: row scan error - %v", err)
			continue
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[users] get all failed: row iteration error - %v", err)
		http.Error(w, "Error processing users", http.StatusInternalServerError)
		return
	}

	log.Printf("[users] retrieved %d users successfully", len(users))
	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Printf("[users] failed to encode response: %v", err)
	}
}

// createUser adds a new user with a hashed password.
// Request: {"credentials": {"username": "jdoe", "password": "secret"}, "role_id": 1}
// Response: 201 Created with user details | 400 Bad Request | 409 Conflict
func createUser(w http.ResponseWriter, r *http.Request) {
	var newUser models.UserWithCredentials
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		log.Printf("[users] create failed: invalid request body - %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if !UsernameRE.MatchString(newUser.Credentials.Username) {
		log.Printf("[users] create failed: invalid username format '%s'", newUser.Credentials.Username)
		http.Error(w, "Invalid username format", http.StatusBadRequest)
		return
	}

	if err := utils.ValidatePasswordComplexity(newUser.Credentials.Password); err != nil {
		log.Printf("[users] create failed for '%s': weak password", newUser.Credentials.Username)
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	if newUser.RoleId == 0 {
		log.Printf("[users] create failed for '%s': missing role_id", newUser.Credentials.Username)
		http.Error(w, "User role_id is required", http.StatusBadRequest)
		return
	}

	hashedPwd, err := utils.HashPassword(newUser.Credentials.Password)
	if err != nil {
		log.Printf("[users] create failed for '%s': password hashing error - %v", newUser.Credentials.Username, err)
		http.Error(w, "Internal server error processing credentials", http.StatusInternalServerError)
		return
	}

	result, err := database.DB.Exec("INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)",
		newUser.Credentials.Username, hashedPwd, newUser.RoleId)
	if err != nil {
		log.Printf("[users] create failed for '%s': database insert error - %v", newUser.Credentials.Username, err)
		http.Error(w, "Error creating user (name must be unique)", http.StatusConflict)
		return
	}

	if id, err := result.LastInsertId(); err == nil {
		newUser.Id = int(id)
	}

	log.Printf("[users] created user '%s' successfully with ID %d", newUser.Credentials.Username, newUser.Id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	newUser.Credentials.Password = ""
	if err := json.NewEncoder(w).Encode(newUser); err != nil {
		log.Printf("[users] failed to encode response: %v", err)
	}
}

// DeleteUser removes a user by ID.
// Input:  Path param {id}
// Output: 200 OK | 400 Bad Request | 404 Not Found | 403 Forbidden
func deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Check if target user is root
	var targetRoleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, id).Scan(&targetRoleName)

	if err == nil && targetRoleName == "root" {
		// Get current user role
		username, ok := r.Context().Value(userKey).(string)
		if ok {
			var currentRoleName string
			err = database.DB.QueryRow(`
				SELECT r.name FROM users u
				INNER JOIN roles r ON u.role_id = r.id
				WHERE u.username = ?`, username).Scan(&currentRoleName)
			if err != nil {
				log.Printf("[users] failed to get role for user '%s': %v", username, err)
				http.Error(w, "Failed to get user role", http.StatusInternalServerError)
			}

			if currentRoleName != "root" {
				log.Printf("[users] admin '%s' attempted to delete root user", username)
				http.Error(w, "Forbidden: Cannot delete root user", http.StatusForbidden)
				return
			}
		}
	}

	res, err := database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		log.Printf("[users] delete failed for ID %d: database error - %v", id, err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[users] delete failed: user ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("[users] deleted user ID %d successfully", id)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("User deleted successfully")); err != nil {
		log.Printf("[users] failed to write response: %v", err)
	}
}

// UpdateUserRole modifies the role assigned to a user.
// Input:  Path param {id} and {"role_id": 2}
// Output: 200 OK | 400 Bad Request | 404 Not Found | 403 Forbidden
func updateUserRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		RoleId int `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[users] update role failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Check if target user is root
	var targetRoleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, id).Scan(&targetRoleName)

	if err == nil && targetRoleName == "root" {
		// Get current user role
		username, ok := r.Context().Value(userKey).(string)
		if ok {
			var currentRoleName string
			err = database.DB.QueryRow(`
				SELECT r.name FROM users u
				INNER JOIN roles r ON u.role_id = r.id
				WHERE u.username = ?`, username).Scan(&currentRoleName)
			if err != nil {
				log.Printf("[users] failed to get role for user '%s': %v", username, err)
				http.Error(w, "Failed to get user role", http.StatusInternalServerError)
			}

			if currentRoleName != "root" {
				log.Printf("[users] admin '%s' attempted to modify root user role", username)
				http.Error(w, "Forbidden: Cannot modify root user role", http.StatusForbidden)
				return
			}
		}
	}

	res, err := database.DB.Exec("UPDATE users SET role_id = ? WHERE id = ?", req.RoleId, id)
	if err != nil {
		log.Printf("[users] update role failed for ID %d: database error - %v", id, err)
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[users] update role failed: user ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("[users] updated role for user ID %d to role %d successfully", id, req.RoleId)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("User role updated successfully")); err != nil {
		log.Printf("[users] failed to write response: %v", err)
	}
}

// ResetUserPassword forces a password change for a specific user.
// Input:  Path param {id} and {"password": "new_secret_123"}
// Output: 200 OK | 400 Bad Request | 404 Not Found | 403 Forbidden
func resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[users] reset password failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Check if target user is root
	var targetRoleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, id).Scan(&targetRoleName)

	if err == nil && targetRoleName == "root" {
		// Get current user role
		username, ok := r.Context().Value(userKey).(string)
		if ok {
			var currentRoleName string
			err = database.DB.QueryRow(`
				SELECT r.name FROM users u
				INNER JOIN roles r ON u.role_id = r.id
				WHERE u.username = ?`, username).Scan(&currentRoleName)
			if err != nil {
				log.Printf("[users] failed to get role for user '%s': %v", username, err)
				http.Error(w, "Failed to get user role", http.StatusInternalServerError)
			}

			if currentRoleName != "root" {
				log.Printf("[users] admin '%s' attempted to reset root user password", username)
				http.Error(w, "Forbidden: Cannot reset root user password", http.StatusForbidden)
				return
			}
		}
	}

	if err := utils.ValidatePasswordComplexity(req.Password); err != nil {
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		log.Printf("[users] reset password failed for ID %d: hashing error - %v", id, err)
		http.Error(w, "Internal server error processing credentials", http.StatusInternalServerError)
		return
	}

	res, err := database.DB.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, id)
	if err != nil {
		log.Printf("[users] reset password failed for ID %d: database error - %v", id, err)
		http.Error(w, "Failed to reset user password", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[users] reset password failed: user ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("[users] reset password successfully for user ID %d", id)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("User password reset successfully")); err != nil {
		log.Printf("[users] failed to write response: %v", err)
	}
}

// GetUserServices retrieves specific extra services assigned to a user.
// Input:  Path param {id}
// Output: 200 OK (JSON list of services) | 400 Bad Request | 500 Internal Error
func getUserServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	// Direct user services (via user_extra_services)
	rows, err := database.DB.Query(`
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN user_extra_services ues ON s.id = ues.service_id
		WHERE ues.user_id = ?`, userID)
	if err != nil {
		log.Printf("[users] get services failed for user ID %d: database query error - %v", userID, err)
		http.Error(w, "Failed to retrieve user services", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[users] failed to close rows: %v", err)
		}
	}()

	// Initialize as empty slice to return [] instead of null
	services := make([]models.Service, 0, 5)

	for rows.Next() {
		var s models.Service
		var desc sql.NullString

		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err != nil {
			log.Printf("[users] get services: row scan error. %v", err)
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[users] get services failed: row iteration error. %v", err)
		http.Error(w, "Error processing services", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("[users] failed to encode response: %v", err)
	}
}

// AddUserService grants an *extra* specific service permission to a user.
// Input:  Path {id} and JSON body {"service_id": 5}
// Output: 200 OK | 400 Bad Request | 403 Forbidden
func addUserService(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid User ID in URL", http.StatusBadRequest)
		return
	}

	// Check if target user is root
	var targetRoleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, userID).Scan(&targetRoleName)

	if err == nil && targetRoleName == "root" {
		// Get current user role
		username, ok := r.Context().Value(userKey).(string)
		if ok {
			var currentRoleName string
			err = database.DB.QueryRow(`
				SELECT r.name FROM users u
				INNER JOIN roles r ON u.role_id = r.id
				WHERE u.username = ?`, username).Scan(&currentRoleName)
			if err != nil {
				log.Printf("[users] failed to get role for user '%s': %v", username, err)
				http.Error(w, "Failed to get user role", http.StatusInternalServerError)
			}

			if currentRoleName != "root" {
				log.Printf("[users] admin '%s' attempted to modify root user services", username)
				http.Error(w, "Forbidden: Cannot modify root user services", http.StatusForbidden)
				return
			}
		}
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[users] add service failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Insert into user_extra_services
	_, err = database.DB.Exec("INSERT OR IGNORE INTO user_extra_services (user_id, service_id) VALUES (?, ?)",
		userID, req.ServiceID)
	if err != nil {
		log.Printf("[users] add service failed for user %d and service %d: database error - %v", userID, req.ServiceID, err)
		http.Error(w, "Failed to assign service to user (check if IDs exist)", http.StatusBadRequest)
		return
	}

	log.Printf("[users] added service %d to user %d successfully", req.ServiceID, userID)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service assigned to user successfully")); err != nil {
		log.Printf("[users] failed to write response: %v", err)
	}
}

// RemoveUserService revokes an *extra* service permission from a user.
// Input:  Path {id} (User ID) and {svc_id} (Service ID)
// Output: 200 OK | 400 Bad Request | 403 Forbidden | 500 Internal Error
func removeUserService(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid User ID in URL", http.StatusBadRequest)
		return
	}

	// Check if target user is root
	var targetRoleName string
	err = database.DB.QueryRow(`
		SELECT r.name FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.id = ?`, userID).Scan(&targetRoleName)

	if err == nil && targetRoleName == "root" {
		// Get current user role
		username, ok := r.Context().Value(userKey).(string)
		if ok {
			var currentRoleName string
			err = database.DB.QueryRow(`
				SELECT r.name FROM users u
				INNER JOIN roles r ON u.role_id = r.id
				WHERE u.username = ?`, username).Scan(&currentRoleName)
			if err != nil {
				log.Printf("[users] failed to get role for user '%s': %v", username, err)
				http.Error(w, "Failed to get user role", http.StatusInternalServerError)
			}

			if currentRoleName != "root" {
				log.Printf("[users] admin '%s' attempted to modify root user services", username)
				http.Error(w, "Forbidden: Cannot modify root user services", http.StatusForbidden)
				return
			}
		}
	}

	svcID, err := strconv.Atoi(r.PathValue("svc_id"))
	if err != nil {
		http.Error(w, "Invalid Service ID in URL", http.StatusBadRequest)
		return
	}

	// Delete from user_extra_services only
	res, err := database.DB.Exec("DELETE FROM user_extra_services WHERE user_id = ? AND service_id = ?", userID, svcID)
	if err != nil {
		log.Printf("[users] remove service failed for user %d and service %d: database error - %v", userID, svcID, err)
		http.Error(w, "Failed to remove service from user", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[users] remove service: no assignment found for user %d and service %d", userID, svcID)
	} else {
		log.Printf("[users] removed service %d from user %d successfully", svcID, userID)
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service removed from user successfully")); err != nil {
		log.Printf("[users] failed to write response: %v", err)
	}
}
