package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"Aegis/controller/proto"
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// getMyServices returns all services the user can access (role-based plus extra assigned services).
// Response: 200 OK with service list | 401 Unauthorized | 500 Internal Server Error
func getMyServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, roleID, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Logic: Union of Role-based services AND User-specific extra services
	rows, err := database.DB.Query(`
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN role_services rs ON s.id = rs.service_id
		WHERE rs.role_id = ?
		UNION
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at
		FROM services s
		JOIN user_extra_services ues ON s.id = ues.service_id
		WHERE ues.user_id = ?`, roleID, userID)

	if err != nil {
		log.Printf("[dashboard] get my services failed for user ID %d: database error - %v", userID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[dashboard] failed to close rows: %v", err)
		}
	}()

	services := make([]models.Service, 0, 10)
	for rows.Next() {
		var s models.Service
		var desc sql.NullString
		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err == nil {
			s.Description = desc.String
			services = append(services, s)
		}
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("[dashboard] failed to encode response: %v", err)
	}
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

	rows, err := database.DB.Query(`
		SELECT s.id, s.name, s.ip_port, s.description, s.created_at, uas.time_left, uas.updated_at
		FROM services s
		JOIN user_active_services uas ON s.id = uas.service_id
		WHERE uas.user_id = ?
		ORDER BY uas.updated_at DESC`, userID)

	if err != nil {
		log.Printf("[dashboard] get active services failed: database error - %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[dashboard] failed to close rows: %v", err)
		}
	}()

	services := make([]models.ActiveService, 0, 5)
	for rows.Next() {
		var as models.ActiveService
		var desc sql.NullString
		if err := rows.Scan(&as.Id, &as.Name, &as.IpPort, &desc, &as.CreatedAt, &as.TimeLeft, &as.UpdatedAt); err == nil {
			as.Description = desc.String
			services = append(services, as)
		}
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("[dashboard] failed to encode response: %v", err)
	}
}

// SelectActiveService adds or refreshes a service in the active list.
// This handles the 5-10s updates efficiently using Upsert logic.
func selectActiveService(w http.ResponseWriter, r *http.Request) {
	userID, roleID, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var exists int
	err = database.DB.QueryRow(`
		SELECT 1 FROM role_services WHERE role_id = ? AND service_id = ?
		UNION
		SELECT 1 FROM user_extra_services WHERE user_id = ? AND service_id = ?`,
		roleID, req.ServiceID, userID, req.ServiceID).Scan(&exists)

	if err == sql.ErrNoRows {
		http.Error(w, "Forbidden: You do not have access to this service", http.StatusForbidden)
		return
	} else if err != nil {
		log.Printf("[dashboard] select service failed: permission check error - %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse service IP and port
	dstIP, dstPort, err := parseServiceIPPort(req.ServiceID)
	if err != nil {
		log.Printf("[dashboard] select service failed: service lookup/parse error - %v", err)
		http.Error(w, "Service not found or invalid configuration", http.StatusInternalServerError)
		return
	}

	// Get client IP
	clientIP := utils.GetClientIP(r)
	log.Printf("[dashboard] activating service ID %d for user ID %d from IP %s to %s:%d", req.ServiceID, userID, clientIP, dstIP, dstPort)

	// Call SendSessionData to activate the session
	success, err := proto.SendSessionData(clientIP, dstIP, dstPort, true, time.Second)
	if err != nil {
		log.Printf("[dashboard] SendSessionData failed for service ID %d: %v", req.ServiceID, err)
		http.Error(w, "Failed to activate session", http.StatusInternalServerError)
		return
	}
	if !success {
		log.Printf("[dashboard] SendSessionData returned false for service ID %d", req.ServiceID)
		http.Error(w, "Session activation failed", http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec("INSERT OR REPLACE INTO user_active_services (user_id, service_id, updated_at, time_left) VALUES (?, ?, ?, ?)",
		userID, req.ServiceID, time.Now(), 60)
	if err != nil {
		log.Printf("[dashboard] select service failed: database write error - %v", err)
		http.Error(w, "Failed to update active status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service set to active")); err != nil {
		log.Printf("[dashboard] failed to write response: %v", err)
	}
}

// DeselectActiveService removes a service from the monitoring list.
func deselectActiveService(w http.ResponseWriter, r *http.Request) {
	userID, _, err := resolveCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	svcID, err := strconv.Atoi(r.PathValue("svc_id"))
	if err != nil {
		http.Error(w, "Invalid Service ID", http.StatusBadRequest)
		return
	}

	// Parse service IP and port
	dstIP, dstPort, err := parseServiceIPPort(svcID)
	if err != nil {
		log.Printf("[dashboard] deselect service failed: service lookup/parse error - %v", err)
		http.Error(w, "Service not found or invalid configuration", http.StatusInternalServerError)
		return
	}

	// Get client IP
	clientIP := utils.GetClientIP(r)
	log.Printf("[dashboard] deactivating service ID %d for user ID %d from IP %s to %s:%d", svcID, userID, clientIP, dstIP, dstPort)

	// Call SendSessionData to deactivate the session
	success, err := proto.SendSessionData(clientIP, dstIP, dstPort, false, time.Second)
	if err != nil {
		log.Printf("[dashboard] SendSessionData failed for service ID %d deactivation: %v", svcID, err)
	} else if !success {
		log.Printf("[dashboard] SendSessionData returned false for service ID %d deactivation", svcID)
	}

	_, err = database.DB.Exec("DELETE FROM user_active_services WHERE user_id = ? AND service_id = ?", userID, svcID)
	if err != nil {
		log.Printf("[dashboard] deselect service failed: database error - %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service removed from active list")); err != nil {
		log.Printf("[dashboard] failed to write response: %v", err)
	}
}

func resolveCurrentUser(r *http.Request) (int, int, error) {
	username, ok := r.Context().Value(userKey).(string)
	if !ok || username == "" {
		return 0, 0, sql.ErrNoRows
	}

	id, roleID, err := database.GetUserIDAndRole(username)
	return id, roleID, err
}

// parseServiceIPPort retrieves and parses service IP and port from database.
// Returns destination IP, port.
func parseServiceIPPort(serviceID int) (string, uint32, error) {
	var ipPort string
	err := database.DB.QueryRow("SELECT ip_port FROM services WHERE id = ?", serviceID).Scan(&ipPort)
	if err != nil {
		return "", 0, err
	}

	// Use net.SplitHostPort to properly handle both IPv4:port and [IPv6]:port formats
	host, portStr, err := net.SplitHostPort(ipPort)
	if err != nil {
		return "", 0, err
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return "", 0, err
	}

	return host, uint32(port), nil
}
