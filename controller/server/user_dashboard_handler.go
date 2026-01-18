package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

// GetMyServices returns ALL services the user has permission to see (Role + Extra).
// This is the "Catalog" view.
func getMyServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, roleID, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Logic: Union of Role-based services AND User-specific extra services
	query := `
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN role_services rs ON s.id = rs.service_id
		WHERE rs.role_id = ?
		UNION
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN user_extra_services ues ON s.id = ues.service_id
		WHERE ues.user_id = ?`

	rows, err := database.DB.Query(query, roleID, userID)
	if err != nil {
		log.Printf("GetMyServices: DB Error for User %d: %v", userID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	services := []models.Service{}
	for rows.Next() {
		var s models.Service
		var desc sql.NullString
		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err == nil {
			s.Description = desc.String
			services = append(services, s)
		}
	}

	json.NewEncoder(w).Encode(services)
}

// GetMyActiveServices returns only the services currently in the 'user_active_services' table.
// This is the "Dashboard" / "Live" view.
func getMyActiveServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, _, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query := `
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN user_active_services uas ON s.id = uas.service_id
		WHERE uas.user_id = ?
		ORDER BY uas.updated_at DESC` // Shows most recently updated/added first

	rows, err := database.DB.Query(query, userID)
	if err != nil {
		log.Printf("GetMyActiveServices: DB Error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	services := []models.Service{}
	for rows.Next() {
		var s models.Service
		var desc sql.NullString
		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err == nil {
			s.Description = desc.String
			services = append(services, s)
		}
	}

	json.NewEncoder(w).Encode(services)
}

// SelectActiveService adds or refreshes a service in the active list.
// This handles the 5-10s updates efficiently using Upsert logic.
func selectActiveService(w http.ResponseWriter, r *http.Request) {
	userID, roleID, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var params struct {
		ServiceID int `json:"service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Verify Permission: Does the user actually have access to this service?
	// We check both Role permissions and User Extra permissions.
	permQuery := `
		SELECT 1 FROM role_services WHERE role_id = ? AND service_id = ?
		UNION
		SELECT 1 FROM user_extra_services WHERE user_id = ? AND service_id = ?`

	var exists int
	err = database.DB.QueryRow(permQuery, roleID, params.ServiceID, userID, params.ServiceID).Scan(&exists)

	if err == sql.ErrNoRows {
		http.Error(w, "Forbidden: You do not have access to this service", http.StatusForbidden)
		return
	} else if err != nil {
		log.Printf("SelectActiveService: Perm check failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 2. Upsert: Insert or Update Timestamp
	// "INSERT OR REPLACE" is SQLite syntax.
	// For MySQL/Postgres use: "INSERT ... ON DUPLICATE KEY UPDATE updated_at = NOW()"
	query := `INSERT OR REPLACE INTO user_active_services (user_id, service_id, updated_at) VALUES (?, ?, ?)`

	_, err = database.DB.Exec(query, userID, params.ServiceID, time.Now())
	if err != nil {
		log.Printf("SelectActiveService: DB Write failed: %v", err)
		http.Error(w, "Failed to update active status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service set to active"))
}

// DeselectActiveService removes a service from the monitoring list.
func deselectActiveService(w http.ResponseWriter, r *http.Request) {
	userID, _, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	svcIDStr := r.PathValue("svc_id") // Go 1.22+ syntax
	svcID, err := strconv.Atoi(svcIDStr)
	if err != nil {
		http.Error(w, "Invalid Service ID", http.StatusBadRequest)
		return
	}

	query := "DELETE FROM user_active_services WHERE user_id = ? AND service_id = ?"
	_, err = database.DB.Exec(query, userID, svcID)
	if err != nil {
		log.Printf("DeselectActiveService: DB Error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service removed from active list"))
}

// --- Helper ---

func resolveCurrentUser(r *http.Request) (int, int, error) {
	// 'userKey' must be defined in your auth_handler or middleware file
	val := r.Context().Value(userKey)
	username, ok := val.(string)
	if !ok || username == "" {
		return 0, 0, sql.ErrNoRows
	}

	var id, roleID int
	err := database.DB.QueryRow("SELECT id, role_id FROM users WHERE username = ?", username).Scan(&id, &roleID)
	return id, roleID, err
}
