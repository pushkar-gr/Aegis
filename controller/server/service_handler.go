package server

import (
	"Aegis/controller/database"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// getServices retrieves all available services from the database.
// Response: 200 OK with service list | 500 Internal Server Error
func getServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := database.DB.Query("SELECT id, name, hostname, ip_port, description, created_at FROM services")
	if err != nil {
		log.Printf("[services] get all failed: database query error. %v", err)
		http.Error(w, "Failed to retrieve services", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[services] failed to close rows: %v", err)
		}
	}()

	services := make([]models.Service, 0, 10)
	for rows.Next() {
		var s models.Service
		var desc sql.NullString

		if err := rows.Scan(&s.Id, &s.Name, &s.Hostname, &s.IpPort, &desc, &s.CreatedAt); err != nil {
			log.Printf("[services] get all: row scan error. %v", err)
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[services] get all failed: row iteration error. %v", err)
		http.Error(w, "Error processing services", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("[services] failed to encode response: %v", err)
	}
}

// createService adds a new service to the system.
// Request: {"name": "Auth", "hostname": "hostname:8080", "description": "Auth Service"}
// Output: 201 Created (JSON Service) | 400 Bad Request | 409 Conflict
func createService(w http.ResponseWriter, r *http.Request) {
	var newService models.Service
	if err := json.NewDecoder(r.Body).Decode(&newService); err != nil {
		log.Printf("[services] create failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if newService.Name == "" || newService.Hostname == "" {
		http.Error(w, "Service name and hostname are required", http.StatusBadRequest)
		return
	}

	host, port, err := net.SplitHostPort(newService.Hostname)
	if err != nil {
		log.Printf("[services] invalid address format '%s': %v", newService.Hostname, err)
		http.Error(w, fmt.Sprintf("Invalid hostname format '%s': %v. Use hostname:port format", newService.Hostname, err), http.StatusBadRequest)
		return
	}

	// Check if host is already an IP address to avoid DNS lookup
	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		// Host is already an IP address, use it
		resolvedIP = host
	} else {
		// Host is a hostname, resolve it to IP
		ips, err := utils.ResolveHostname(host)
		if err != nil || len(ips) == 0 {
			log.Printf("[services] failed to resolve hostname '%s': %v", host, err)
			http.Error(w, fmt.Sprintf("DNS resolution failed for hostname '%s': %v", host, err), http.StatusBadRequest)
			return
		}
		resolvedIP = ips[0]
	}

	newService.IpPort = net.JoinHostPort(resolvedIP, port)

	result, err := database.DB.Exec(
		"INSERT INTO services (name, hostname, ip_port, description) VALUES (?, ?, ?, ?)",
		newService.Name, newService.Hostname, newService.IpPort, newService.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			log.Printf("[services] create failed for '%s': service name already exists", newService.Name)
			http.Error(w, fmt.Sprintf("Service with name '%s' already exists", newService.Name), http.StatusConflict)
			return
		}
		log.Printf("[services] insert failed: %v", err)
		http.Error(w, "Failed to create service", http.StatusInternalServerError)
		return
	}

	if id, err := result.LastInsertId(); err == nil {
		newService.Id = int(id)
	}

	log.Printf("[services] created service '%s' (ID: %d) | Host: %s -> IP: %s", newService.Name, newService.Id, newService.Hostname, newService.IpPort)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(newService); err != nil {
		log.Printf("[services] failed to encode response: %v", err)
	}
}

// updateService modifies an existing service by ID.
// Request: Path param {id} and {"name": "...", "hostname": "...", "description": "..."}
// Output: 200 OK (JSON Service) | 400 Bad Request | 404 Not Found
func updateService(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid service ID", http.StatusBadRequest)
		return
	}

	var service models.Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		log.Printf("[services] update failed: invalid request body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if service.Name == "" || service.Hostname == "" {
		http.Error(w, "Service name and hostname are required", http.StatusBadRequest)
		return
	}

	host, port, err := net.SplitHostPort(service.Hostname)
	if err != nil {
		log.Printf("[services] invalid address format '%s': %v", service.Hostname, err)
		http.Error(w, fmt.Sprintf("Invalid hostname format '%s': %v. Use hostname:port format", service.Hostname, err), http.StatusBadRequest)
		return
	}

	// Check if host is already an IP address to avoid DNS lookup
	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		// Host is already an IP address, use it
		resolvedIP = host
	} else {
		// Host is a hostname, resolve it to IP
		ips, err := utils.ResolveHostname(host)
		if err != nil || len(ips) == 0 {
			log.Printf("[services] failed to resolve hostname '%s': %v", host, err)
			http.Error(w, fmt.Sprintf("DNS resolution failed for hostname '%s': %v", host, err), http.StatusBadRequest)
			return
		}
		resolvedIP = ips[0]
	}

	service.IpPort = net.JoinHostPort(resolvedIP, port)

	result, err := database.DB.Exec(
		"UPDATE services SET name=?, hostname=?, ip_port=?, description=? WHERE id=?",
		service.Name, service.Hostname, service.IpPort, service.Description, id,
	)
	if err != nil {
		// Check for UNIQUE constraint violation
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			log.Printf("[services] update failed for ID %d: service name '%s' already exists", id, service.Name)
			http.Error(w, fmt.Sprintf("Service with name '%s' already exists", service.Name), http.StatusConflict)
			return
		}
		log.Printf("[services] update failed for ID %d: %v", id, err)
		http.Error(w, "Failed to update service", http.StatusInternalServerError)
		return
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		log.Printf("[services] update failed: service ID %d not found", id)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	service.Id = id
	log.Printf("[services] updated service '%s' (ID: %d) | Host: %s -> IP: %s", service.Name, service.Id, service.Hostname, service.IpPort)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(service); err != nil {
		log.Printf("[services] failed to encode response: %v", err)
	}
}

// deleteService removes a service by ID.
// Request: Path param {id}
// Output: 200 OK | 400 Bad Request | 404 Not Found
func deleteService(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid service ID", http.StatusBadRequest)
		return
	}

	res, err := database.DB.Exec("DELETE FROM services WHERE id = ?", id)
	if err != nil {
		log.Printf("[services] delete failed for ID %d: database error. %v", id, err)
		http.Error(w, "Failed to delete service", http.StatusInternalServerError)
		return
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		log.Printf("[services] delete failed: service ID %d not found", id)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	log.Printf("[services] deleted service ID %d successfully", id)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service deleted successfully")); err != nil {
		log.Printf("[services] failed to write response: %v", err)
	}
}
