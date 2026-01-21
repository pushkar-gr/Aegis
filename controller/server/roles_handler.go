package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

// getRoles retrieves all available roles from the database.
// Input:  None
// Output: 200 OK (JSON list of roles) | 500 Internal Error
func getRoles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := database.DB.Query("SELECT id, name, description FROM roles")
	if err != nil {
		log.Printf("[roles] get all failed: database query error. %v", err)
		http.Error(w, "Failed to retrieve roles", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[roles] failed to close rows: %v", err)
		}
	}()

	roles := make([]models.Role, 0, 5)
	for rows.Next() {
		var r models.Role
		var desc sql.NullString

		if err := rows.Scan(&r.Id, &r.Name, &desc); err != nil {
			log.Printf("[roles] get all: row scan error. %v", err)
			continue
		}
		r.Description = desc.String
		roles = append(roles, r)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[roles] get all failed: row iteration error. %v", err)
		http.Error(w, "Error processing roles", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(roles); err != nil {
		log.Printf("[roles] failed to encode response: %v", err)
	}
}

// createRole adds a new user role to the system.
// Request: {"name": "editor", "description": "Can edit posts"}
// Output: 201 Created (JSON Role) | 400 Bad Request | 409 Conflict (Duplicate)
func createRole(w http.ResponseWriter, r *http.Request) {
	var newRole models.Role
	if err := json.NewDecoder(r.Body).Decode(&newRole); err != nil {
		log.Printf("[roles] create failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if newRole.Name == "" {
		http.Error(w, "Role name is required", http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec("INSERT INTO roles (name, description) VALUES (?, ?)",
		newRole.Name, newRole.Description)
	if err != nil {
		log.Printf("[roles] create failed for '%s': database insert error - %v", newRole.Name, err)
		http.Error(w, "Error creating role (name must be unique)", http.StatusConflict)
		return
	}

	if id, err := result.LastInsertId(); err == nil {
		newRole.Id = int(id)
	}

	log.Printf("[roles] created role '%s' created (ID: %d)", newRole.Name, newRole.Id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(newRole); err != nil {
		log.Printf("[roles] failed to encode response: %v", err)
	}
}

// deleteRole removes a role by ID.
// Input:  Query param ?id=123
// Output: 200 OK | 400 Bad Request | 404 Not Found
func deleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	res, err := database.DB.Exec("DELETE FROM roles WHERE id = ?", id)
	if err != nil {
		log.Printf("[roles] delete failed for ID %d: database error. %v", id, err)
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[roles] delete failed: role ID %d not found", id)
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	log.Printf("[roles] deleted role ID %d successfully", id)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Role deleted successfully")); err != nil {
		log.Printf("[roles] failed to write response: %v", err)
	}
}

// getRoleServices retrieves all services assigned to a specific role.
// Request: Path param {id} for role ID
// Output: 200 OK (JSON list of services) | 400 Bad Request | 500 Internal Error
func getRoleServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	roleID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid Role ID", http.StatusBadRequest)
		return
	}

	rows, err := database.DB.Query(`
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		INNER JOIN role_services rs ON s.id = rs.service_id
		WHERE rs.role_id = ?`, roleID)

	if err != nil {
		log.Printf("[roles] get services failed for role ID %d: database query error. %v", roleID, err)
		http.Error(w, "Failed to retrieve role services", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[roles] failed to close rows: %v", err)
		}
	}()

	services := make([]models.Service, 0, 5)

	for rows.Next() {
		var s models.Service
		var desc sql.NullString

		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err != nil {
			log.Printf("[roles] get services: row scan error. %v", err)
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[roles] get services failed: row iteration error. %v", err)
		http.Error(w, "Error processing services", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("[roles] failed to encode response: %v", err)
	}
}

// addRoleService links a service to a role.
// Request: Path param {id} for role and {"service_id": 5}
// Output: 200 OK | 400 Bad Request
func addRoleService(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid Role ID in URL", http.StatusBadRequest)
		return
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[roles] add service failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	_, err = database.DB.Exec("INSERT OR IGNORE INTO role_services (role_id, service_id) VALUES (?, ?)",
		roleID, req.ServiceID)
	if err != nil {
		log.Printf("[roles] add service failed for role %d and service %d: database error - %v", roleID, req.ServiceID, err)
		http.Error(w, "Failed to link service to role (check if IDs exist)", http.StatusBadRequest)
		return
	}

	log.Printf("[roles] added service %d to role %d successfully", req.ServiceID, roleID)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service added to role successfully")); err != nil {
		log.Printf("[roles] failed to write response: %v", err)
	}
}

// removeRoleService unlinks a service from a role.
// Request: Path params {id} for role and {svc_id} for service
// Output: 200 OK | 400 Bad Request
func removeRoleService(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid Role ID in URL", http.StatusBadRequest)
		return
	}

	svcID, err := strconv.Atoi(r.PathValue("svc_id"))
	if err != nil {
		http.Error(w, "Invalid Service ID in URL", http.StatusBadRequest)
		return
	}

	_, err = database.DB.Exec("DELETE FROM role_services WHERE role_id = ? AND service_id = ?", roleID, svcID)
	if err != nil {
		log.Printf("[roles] remove service failed for role %d and service %d: database error - %v", roleID, svcID, err)
		http.Error(w, "Failed to remove service from role", http.StatusInternalServerError)
		return
	}

	log.Printf("[roles] removed service %d from role %d successfully", svcID, roleID)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service removed from role successfully")); err != nil {
		log.Printf("[roles] failed to write response: %v", err)
	}
}
