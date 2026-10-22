package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ServiceHandler handles service management and user dashboard endpoints.
type ServiceHandler struct {
	svcSvc   service.ServiceService
	userRepo repository.UserRepository
}

// NewServiceHandler creates a new ServiceHandler.
func NewServiceHandler(svcSvc service.ServiceService, userRepo repository.UserRepository) *ServiceHandler {
	return &ServiceHandler{svcSvc: svcSvc, userRepo: userRepo}
}

// GetAll returns all services (admin).
func (h *ServiceHandler) GetAll(c *gin.Context) {
	services, err := h.svcSvc.GetAll()
	if err != nil {
		log.Printf("[services] get all failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve services"})
		return
	}
	c.JSON(http.StatusOK, services)
}

// Create adds a new service.
func (h *ServiceHandler) Create(c *gin.Context) {
	var newService models.Service
	if err := c.ShouldBindJSON(&newService); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	result, err := h.svcSvc.Create(newService.Name, newService.Hostname, newService.Description)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrServiceNameExists):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case errors.Is(err, service.ErrServiceInputRequired), errors.Is(err, service.ErrInvalidHostname):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			log.Printf("[services] create failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service"})
		}
		return
	}

	log.Printf("[services] created service '%s' (ID: %d)", result.Name, result.Id)
	c.JSON(http.StatusCreated, result)
}

// Update modifies an existing service.
func (h *ServiceHandler) Update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	var svc models.Service
	if err := c.ShouldBindJSON(&svc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	result, err := h.svcSvc.Update(id, svc.Name, svc.Hostname, svc.Description)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrServiceNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		case errors.Is(err, service.ErrServiceNameExists):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case errors.Is(err, service.ErrServiceInputRequired), errors.Is(err, service.ErrInvalidHostname):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			log.Printf("[services] update failed for ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update service"})
		}
		return
	}

	log.Printf("[services] updated service '%s' (ID: %d)", result.Name, result.Id)
	c.JSON(http.StatusOK, result)
}

// Delete removes a service by ID.
func (h *ServiceHandler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	if err := h.svcSvc.Delete(id); err != nil {
		if errors.Is(err, service.ErrServiceNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		} else {
			log.Printf("[services] delete failed for ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service"})
		}
		return
	}

	log.Printf("[services] deleted service ID %d", id)
	c.String(http.StatusOK, "Service deleted successfully")
}

// currentUser resolves the user ID and role ID of the authenticated user. On
// failure it writes the error response (401 when the user cannot be
// identified, 500 for real failures) and returns ok=false.
func (h *ServiceHandler) currentUser(c *gin.Context) (userID, roleID int, ok bool) {
	username := c.GetString(middleware.UsernameKey)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return 0, 0, false
	}

	userID, roleID, err := h.userRepo.GetIDAndRole(username)
	switch {
	case err == nil:
		return userID, roleID, true
	case errors.Is(err, repository.ErrNotFound):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	default:
		log.Printf("[dashboard] failed to resolve user '%s': %v", username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
	}
	return 0, 0, false
}

// GetMyServices returns all services accessible by the current user.
func (h *ServiceHandler) GetMyServices(c *gin.Context) {
	userID, roleID, ok := h.currentUser(c)
	if !ok {
		return
	}

	services, err := h.svcSvc.GetUserServices(userID, roleID)
	if err != nil {
		log.Printf("[dashboard] get my services failed for user ID %d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, services)
}

// GetMyActiveServices returns the user's currently active services.
func (h *ServiceHandler) GetMyActiveServices(c *gin.Context) {
	userID, _, ok := h.currentUser(c)
	if !ok {
		return
	}

	services, err := h.svcSvc.GetUserActiveServices(userID)
	if err != nil {
		log.Printf("[dashboard] get active services failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, services)
}

// SelectActiveService activates a service for the current user.
func (h *ServiceHandler) SelectActiveService(c *gin.Context) {
	userID, roleID, ok := h.currentUser(c)
	if !ok {
		return
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	clientIP := utils.GetClientIP(c.Request)
	log.Printf("[dashboard] activating service ID %d for user ID %d from IP %s", req.ServiceID, userID, clientIP)

	if err := h.svcSvc.SelectActiveService(userID, roleID, req.ServiceID, clientIP); err != nil {
		switch {
		case errors.Is(err, service.ErrServiceAccessDenied):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You do not have access to this service"})
		case errors.Is(err, service.ErrServiceNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		case errors.Is(err, service.ErrAgentUnavailable):
			log.Printf("[dashboard] activate service %d failed: %v", req.ServiceID, err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent unavailable, try again later"})
		case errors.Is(err, service.ErrAgentRejected):
			log.Printf("[dashboard] activate service %d failed: %v", req.ServiceID, err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "Agent rejected session activation"})
		default:
			log.Printf("[dashboard] activate service %d failed: %v", req.ServiceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate session"})
		}
		return
	}

	c.String(http.StatusOK, "Service set to active")
}

// DeselectActiveService deactivates a service for the current user.
func (h *ServiceHandler) DeselectActiveService(c *gin.Context) {
	userID, _, ok := h.currentUser(c)
	if !ok {
		return
	}

	svcID, err := strconv.Atoi(c.Param("svc_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Service ID"})
		return
	}

	clientIP := utils.GetClientIP(c.Request)
	log.Printf("[dashboard] deactivating service ID %d for user ID %d from IP %s", svcID, userID, clientIP)

	if err := h.svcSvc.DeselectActiveService(userID, svcID, clientIP); err != nil {
		log.Printf("[dashboard] deselect service failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	c.String(http.StatusOK, "Service removed from active list")
}
