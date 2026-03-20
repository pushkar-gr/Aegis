package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
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
		msg := err.Error()
		switch {
		case msg == "service name already exists":
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		case msg == "service name and hostname are required":
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
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
		msg := err.Error()
		switch {
		case msg == "service not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		case msg == "service name already exists":
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
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
		if err.Error() == "service not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service"})
		}
		return
	}

	log.Printf("[services] deleted service ID %d", id)
	c.String(http.StatusOK, "Service deleted successfully")
}

// resolveCurrentUserIDAndRole resolves the user ID and role ID from the Gin context.
func (h *ServiceHandler) resolveCurrentUserIDAndRole(c *gin.Context) (int, int, error) {
	username := c.GetString(middleware.UsernameKey)
	if username == "" {
		return 0, 0, nil
	}
	return h.userRepo.GetIDAndRole(username)
}

// GetMyServices returns all services accessible by the current user.
func (h *ServiceHandler) GetMyServices(c *gin.Context) {
	userID, roleID, err := h.resolveCurrentUserIDAndRole(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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
	userID, _, err := h.resolveCurrentUserIDAndRole(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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
	userID, roleID, err := h.resolveCurrentUserIDAndRole(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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
		msg := err.Error()
		switch {
		case msg == "forbidden: no access to this service":
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You do not have access to this service"})
		case msg == "service not found or invalid configuration":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Service not found or invalid configuration"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate session"})
		}
		return
	}

	c.String(http.StatusOK, "Service set to active")
}

// DeselectActiveService deactivates a service for the current user.
func (h *ServiceHandler) DeselectActiveService(c *gin.Context) {
	userID, _, err := h.resolveCurrentUserIDAndRole(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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
