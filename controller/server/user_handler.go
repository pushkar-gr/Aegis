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

// UsernameRE enforces 5-30 char alphanumeric usernames.
var UsernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")

// GetUsers retrieves all users from the database.
// Input:  None
// Output: 200 OK (JSON list of users) | 500 Internal Error
func getUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := database.DB.Query("SELECT id, username, role_id, is_active FROM users")
	if err != nil {
		log.Printf("GetUsers: DB query failed. %v", err)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User

		if err := rows.Scan(&u.Id, &u.Username, &u.RoleId, &u.IsActive); err != nil {
			log.Printf("GetUsers: Error scanning row. %v", err)
			continue
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		log.Printf("GetUsers: Error iterating rows. %v", err)
		http.Error(w, "Error processing users", http.StatusInternalServerError)
		return
	}

	// Return an empty array instead of null
	if users == nil {
		users = []models.User{}
	}

	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Printf("GetUsers: Encoding response failed. %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// CreateUser adds a new user with a hashed password.
// Input:  {"credentials": {"username": "...", "password": "..."}, "role_id": 1}
// Output: 201 Created (JSON User) | 400 Bad Request | 409 Conflict
func createUser(w http.ResponseWriter, r *http.Request) {
	var newUser models.UserWithCredentials
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		log.Printf("CreateUser: Invalid JSON body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if !UsernameRE.MatchString(newUser.Credentials.Username) {
		http.Error(w, "Invalid username format", http.StatusBadRequest)
		return
	}

	if err := utils.ValidatePasswordComplexity(newUser.Credentials.Password); err != nil {
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	if newUser.RoleId == 0 {
		http.Error(w, "User role_id is required", http.StatusBadRequest)
		return
	}

	var err error
	newUser.Credentials.Password, err = utils.HashPassword(newUser.Credentials.Password)
	if err != nil {
		log.Printf("CreateUser: Error hashing password for '%s'. %v", newUser.Credentials.Username, err)
		http.Error(w, "Internal server error processing credentials", http.StatusInternalServerError)
		return
	}

	query := "INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)"
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		log.Printf("CreateUser: DB prepare failed. %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(newUser.Credentials.Username, newUser.Credentials.Password, newUser.RoleId)
	if err != nil {
		log.Printf("CreateUser: Insert failed for '%s'. %v", newUser.Credentials.Username, err)
		http.Error(w, "Error creating user (name must be unique)", http.StatusConflict)
		return
	}

	id, err := result.LastInsertId()
	if err == nil {
		newUser.Id = int(id)
	}

	log.Printf("CreateUser: User '%s' created (ID: %d)", newUser.Credentials.Username, newUser.Id)
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	newUser.Credentials.Password = "" 
	json.NewEncoder(w).Encode(newUser)
}

// DeleteUser removes a user by ID.
// Input:  Path param {id}
// Output: 200 OK | 400 Bad Request | 404 Not Found
func deleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	query := "DELETE FROM users WHERE id = ?"
	res, err := database.DB.Exec(query, id)
	if err != nil {
		log.Printf("DeleteUser: DB execution failed for ID %d. %v", id, err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("DeleteUser: ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("DeleteUser: User ID %d deleted", id)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}

// UpdateUserRole modifies the role assigned to a user.
// Input:  Path param {id} and {"role_id": 2}
// Output: 200 OK | 400 Bad Request | 404 Not Found
func updateUserRole(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var userRole struct {
		RoleId int `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&userRole); err != nil {
		log.Printf("UpdateUserRole: Invalid JSON body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	query := "UPDATE users SET role_id = ? WHERE id = ?"
	res, err := database.DB.Exec(query, userRole.RoleId, id)
	if err != nil {
		log.Printf("UpdateUserRole: DB execution failed for ID %d. %v", id, err)
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("UpdateUserRole: ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("UpdateUserRole: User ID %d role updated to %d", id, userRole.RoleId)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User role updated successfully"))
}

// ResetUserPassword forces a password change for a specific user.
// Input:  Path param {id} and {"password": "new_secret_123"}
// Output: 200 OK | 400 Bad Request | 404 Not Found
func resetUserPassword(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var userPassword struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&userPassword); err != nil {
		log.Printf("ResetUserPassword: Invalid JSON body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := utils.ValidatePasswordComplexity(userPassword.Password); err != nil {
		http.Error(w, "Password too weak: "+err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(userPassword.Password)
	if err != nil {
		log.Printf("ResetUserPassword: Error hashing password for ID %d. %v", id, err)
		http.Error(w, "Internal server error processing credentials", http.StatusInternalServerError)
		return
	}

	query := "UPDATE users SET password = ? WHERE id = ?"
	res, err := database.DB.Exec(query, hashedPassword, id)
	if err != nil {
		log.Printf("ResetUserPassword: DB execution failed for ID %d. %v", id, err)
		http.Error(w, "Failed to reset user password", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("ResetUserPassword: ID %d not found", id)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("ResetUserPassword: Password reset for User ID %d", id)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User password reset successfully"))
}

// GetUserServices retrieves specific extra services assigned to a user.
// Input:  Path param {id}
// Output: 200 OK (JSON list of services) | 400 Bad Request | 500 Internal Error
func getUserServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := r.PathValue("id")
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	// Direct user services (via user_extra_services)
	query := `
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN user_extra_services ues ON s.id = ues.service_id
		WHERE ues.user_id = ?`

	rows, err := database.DB.Query(query, userID)
	if err != nil {
		log.Printf("GetUserServices: DB query failed for User %d. %v", userID, err)
		http.Error(w, "Failed to retrieve user services", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Initialize as empty slice to return [] instead of null
	services := []models.Service{}

	for rows.Next() {
		var s models.Service
		var desc sql.NullString

		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err != nil {
			log.Printf("GetUserServices: Error scanning row. %v", err)
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}

	if err := rows.Err(); err != nil {
		log.Printf("GetUserServices: Error iterating rows. %v", err)
		http.Error(w, "Error processing services", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("GetUserServices: Encoding response failed. %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// AddUserService grants an *extra* specific service permission to a user.
// Input:  Path {id} and JSON body {"service_id": 5}
// Output: 200 OK | 400 Bad Request
func addUserService(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID in URL", http.StatusBadRequest)
		return
	}

	type ServiceParams struct {
		ServiceID int `json:"service_id"`
	}
	var params ServiceParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("AddUserService: JSON decode failed. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Insert into user_extra_services
	query := "INSERT OR IGNORE INTO user_extra_services (user_id, service_id) VALUES (?, ?)"
	_, err = database.DB.Exec(query, userID, params.ServiceID)
	if err != nil {
		log.Printf("AddUserService: DB link failed (User: %d, Svc: %d). %v", userID, params.ServiceID, err)
		http.Error(w, "Failed to assign service to user (check if IDs exist)", http.StatusBadRequest)
		return
	}

	log.Printf("AddUserService: Assigned extra service %d to user %d", params.ServiceID, userID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service assigned to user successfully"))
}

// RemoveUserService revokes an *extra* service permission from a user.
// Input:  Path {id} (User ID) and {svc_id} (Service ID)
// Output: 200 OK | 400 Bad Request | 500 Internal Error
func removeUserService(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID in URL", http.StatusBadRequest)
		return
	}

	svcIDStr := r.PathValue("svc_id")
	svcID, err := strconv.Atoi(svcIDStr)
	if err != nil {
		http.Error(w, "Invalid Service ID in URL", http.StatusBadRequest)
		return
	}

	// Delete from user_extra_services only
	query := "DELETE FROM user_extra_services WHERE user_id = ? AND service_id = ?"
	res, err := database.DB.Exec(query, userID, svcID)
	if err != nil {
		log.Printf("RemoveUserService: DB unlink failed (User: %d, Svc: %d). %v", userID, svcID, err)
		http.Error(w, "Failed to remove service from user", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("RemoveUserService: No assignment found to delete for User %d, Svc %d", userID, svcID)
	} else {
		log.Printf("RemoveUserService: Removed extra service %d from user %d", svcID, userID)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service removed from user successfully"))
}
