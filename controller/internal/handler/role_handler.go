package handler

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/service"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// RoleHandler handles role management endpoints.
type RoleHandler struct {
	roleSvc service.RoleService
}

// NewRoleHandler creates a new RoleHandler.
func NewRoleHandler(roleSvc service.RoleService) *RoleHandler {
	return &RoleHandler{roleSvc: roleSvc}
}

// GetAll returns all roles.
func (h *RoleHandler) GetAll(c *gin.Context) {
	roles, err := h.roleSvc.GetAll()
	if err != nil {
		log.Printf("[roles] get all failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve roles"})
		return
	}
	c.JSON(http.StatusOK, roles)
}

// Create adds a new role.
func (h *RoleHandler) Create(c *gin.Context) {
	var newRole models.Role
	if err := c.ShouldBindJSON(&newRole); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	result, err := h.roleSvc.Create(newRole.Name, newRole.Description)
	if err != nil {
		msg := err.Error()
		switch msg {
		case "role name is required":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Role name is required"})
		case "role name already exists":
			c.JSON(http.StatusConflict, gin.H{"error": "Error creating role (name must be unique)"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		}
		return
	}

	log.Printf("[roles] created role '%s' (ID: %d)", result.Name, result.Id)
	c.JSON(http.StatusCreated, result)
}

// Delete removes a role by ID.
func (h *RoleHandler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	if err := h.roleSvc.Delete(id); err != nil {
		if err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		}
		return
	}

	log.Printf("[roles] deleted role ID %d", id)
	c.String(http.StatusOK, "Role deleted successfully")
}

// GetServices returns all services assigned to a role.
func (h *RoleHandler) GetServices(c *gin.Context) {
	roleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Role ID"})
		return
	}

	services, err := h.roleSvc.GetServices(roleID)
	if err != nil {
		log.Printf("[roles] get services failed for role ID %d: %v", roleID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve role services"})
		return
	}
	c.JSON(http.StatusOK, services)
}

// AddService links a service to a role.
func (h *RoleHandler) AddService(c *gin.Context) {
	roleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Role ID in URL"})
		return
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	if err := h.roleSvc.AddService(roleID, req.ServiceID); err != nil {
		log.Printf("[roles] add service failed for role %d and service %d: %v", roleID, req.ServiceID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to link service to role (check if IDs exist)"})
		return
	}

	log.Printf("[roles] added service %d to role %d", req.ServiceID, roleID)
	c.String(http.StatusOK, "Service added to role successfully")
}

// RemoveService unlinks a service from a role.
func (h *RoleHandler) RemoveService(c *gin.Context) {
	roleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Role ID in URL"})
		return
	}

	svcID, err := strconv.Atoi(c.Param("svc_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Service ID in URL"})
		return
	}

	if err := h.roleSvc.RemoveService(roleID, svcID); err != nil {
		log.Printf("[roles] remove service failed for role %d and service %d: %v", roleID, svcID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove service from role"})
		return
	}

	log.Printf("[roles] removed service %d from role %d", svcID, roleID)
	c.String(http.StatusOK, "Service removed from role successfully")
}
