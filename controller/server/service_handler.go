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

// GetServices retrieves all available services from the database.
// Input:  None
// Output: 200 OK (JSON list of services) | 500 Internal Error
func getServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := database.DB.Query("SELECT id, name, ip_port, description, created_at FROM services")
	if err != nil {
		log.Printf("GetServices: DB query failed. %v", err)
		http.Error(w, "Failed to retrieve services", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var services []models.Service
	for rows.Next() {
		var s models.Service
		var desc sql.NullString

		if err := rows.Scan(&s.Id, &s.Name, &s.IpPort, &desc, &s.CreatedAt); err != nil {
			log.Printf("GetServices: Error scanning row. %v", err)
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}

	if err := rows.Err(); err != nil {
		log.Printf("GetServices: Error iterating rows. %v", err)
		http.Error(w, "Error processing services", http.StatusInternalServerError)
		return
	}

	// Return an empty array instead of null
	if services == nil {
		services = []models.Service{}
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		log.Printf("GetServices: Encoding response failed. %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// CreateService adds a new service to the system.
// Input:  {"name": "Auth", "ip_port": "localhost:8080", "description": "Auth Service"}
// Output: 201 Created (JSON Service) | 400 Bad Request | 409 Conflict
func createService(w http.ResponseWriter, r *http.Request) {
	var newService models.Service
	if err := json.NewDecoder(r.Body).Decode(&newService); err != nil {
		log.Printf("CreateService: Invalid JSON body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if newService.Name == "" || newService.IpPort == "" {
		http.Error(w, "Service name and ip_port are required", http.StatusBadRequest)
		return
	}

	query := "INSERT INTO services (name, ip_port, description) VALUES (?, ?, ?)"
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		log.Printf("CreateService: DB prepare failed. %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(newService.Name, newService.IpPort, newService.Description)
	if err != nil {
		log.Printf("CreateService: Insert failed for '%s'. %v", newService.Name, err)
		http.Error(w, "Error creating service (name must be unique)", http.StatusConflict)
		return
	}

	id, err := result.LastInsertId()
	if err == nil {
		newService.Id = int(id)
	}

	log.Printf("CreateService: Service '%s' created (ID: %d)", newService.Name, newService.Id)
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newService)
}

// UpdateService modifies an existing service by ID.
// Input:  Path ID and {"name": "...", "ip_port": "...", "description": "..."}
// Output: 200 OK (JSON Service) | 400 Bad Request | 404 Not Found
func updateService(w http.ResponseWriter, r *http.Request) {
	var service models.Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		log.Printf("UpdateService: Invalid JSON body. %v", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if service.Name == "" || service.IpPort == "" {
		http.Error(w, "Service name and ip_port are required", http.StatusBadRequest)
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid service ID", http.StatusBadRequest)
		return
	}
	service.Id = id

	query := "UPDATE services SET name = ?, ip_port = ?, description = ? WHERE id = ?"
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		log.Printf("UpdateService: DB prepare failed. %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(service.Name, service.IpPort, service.Description, service.Id)
	if err != nil {
		log.Printf("UpdateService: Update failed for ID %d. %v", id, err)
		http.Error(w, "Error updating service", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("UpdateService: ID %d not found", id)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	log.Printf("UpdateService: Service '%s' updated (ID: %d)", service.Name, service.Id)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}

// DeleteService removes a service by ID.
// Input:  Query param ?id=123
// Output: 200 OK | 400 Bad Request | 404 Not Found
func deleteService(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid service ID", http.StatusBadRequest)
		return
	}

	query := "DELETE FROM services WHERE id = ?"
	res, err := database.DB.Exec(query, id)
	if err != nil {
		log.Printf("DeleteService: DB execution failed for ID %d. %v", id, err)
		http.Error(w, "Failed to delete service", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("DeleteService: ID %d not found", id)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	log.Printf("DeleteService: Service ID %d deleted", id)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service deleted successfully"))
}
