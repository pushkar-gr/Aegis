package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/service"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	userSvc service.UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userSvc service.UserService) *UserHandler {
	return &UserHandler{userSvc: userSvc}
}

// GetAll returns all users.
func (h *UserHandler) GetAll(c *gin.Context) {
	users, err := h.userSvc.GetAll()
	if err != nil {
		log.Printf("[users] get all failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}
	log.Printf("[users] retrieved %d users successfully", len(users))
	c.JSON(http.StatusOK, users)
}

// Create adds a new user.
func (h *UserHandler) Create(c *gin.Context) {
	var newUser models.UserWithCredentials
	if err := c.ShouldBindJSON(&newUser); err != nil {
		log.Printf("[users] create failed: invalid request body - %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	result, err := h.userSvc.Create(newUser.Credentials.Username, newUser.Credentials.Password, newUser.RoleId, requester)
	if err != nil {
		msg := err.Error()
		switch {
		case errors.Is(err, service.ErrInvalidUsername):
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username format"})
		case errors.Is(err, service.ErrRoleIDRequired):
			c.JSON(http.StatusBadRequest, gin.H{"error": "User role_id is required"})
		case errors.Is(err, service.ErrInvalidRole):
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		case errors.Is(err, service.ErrUsernameExists):
			c.JSON(http.StatusConflict, gin.H{"error": "Error creating user (name must be unique)"})
		case strings.HasPrefix(msg, "password too weak"):
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password" + msg[len("password"):]})
		case errors.Is(err, service.ErrCannotModifyRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot create user with root role"})
		default:
			log.Printf("[users] create failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	log.Printf("[users] created user '%s' successfully with ID %d", newUser.Credentials.Username, result.Id)
	result.Credentials.Password = ""
	c.JSON(http.StatusCreated, result)
}

// Delete removes a user by ID.
func (h *UserHandler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	if err := h.userSvc.Delete(id, requester); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case errors.Is(err, service.ErrCannotModifyRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot delete root user"})
		default:
			log.Printf("[users] delete failed for ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		}
		return
	}

	log.Printf("[users] deleted user ID %d successfully", id)
	c.String(http.StatusOK, "User deleted successfully")
}

// UpdateRole changes the role of a user.
func (h *UserHandler) UpdateRole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		RoleId int `json:"role_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	if err := h.userSvc.UpdateRole(id, req.RoleId, requester); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case errors.Is(err, service.ErrInvalidRole):
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		case errors.Is(err, service.ErrCannotModifyRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot modify root user role"})
		case errors.Is(err, service.ErrCannotBecomeRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot become root user"})
		default:
			log.Printf("[users] update role failed for ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role"})
		}
		return
	}

	log.Printf("[users] updated role for user ID %d to role %d", id, req.RoleId)
	c.String(http.StatusOK, "User role updated successfully")
}

// ResetPassword forces a new password for a user.
func (h *UserHandler) ResetPassword(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	if err := h.userSvc.ResetPassword(id, req.Password, requester); err != nil {
		msg := err.Error()
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case errors.Is(err, service.ErrCannotModifyRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot reset root user password"})
		case strings.HasPrefix(msg, "password too weak"):
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password" + msg[len("password"):]})
		default:
			log.Printf("[users] reset password failed for ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset user password"})
		}
		return
	}

	log.Printf("[users] reset password for user ID %d", id)
	c.String(http.StatusOK, "User password reset successfully")
}

// GetServices returns the extra services assigned to a user.
func (h *UserHandler) GetServices(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}

	services, err := h.userSvc.GetExtraServices(userID)
	if err != nil {
		log.Printf("[users] get services failed for user ID %d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user services"})
		return
	}
	c.JSON(http.StatusOK, services)
}

// AddService grants an extra service to a user.
func (h *UserHandler) AddService(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID in URL"})
		return
	}

	var req struct {
		ServiceID int `json:"service_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	if err := h.userSvc.AddExtraService(userID, req.ServiceID, requester); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case errors.Is(err, service.ErrServiceNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		case errors.Is(err, service.ErrCannotModifyRoot):
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot modify root user services"})
		default:
			log.Printf("[users] add service failed for user %d and service %d: %v", userID, req.ServiceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign service to user"})
		}
		return
	}

	log.Printf("[users] added service %d to user %d", req.ServiceID, userID)
	c.String(http.StatusOK, "Service assigned to user successfully")
}

// RemoveService revokes an extra service from a user.
func (h *UserHandler) RemoveService(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID in URL"})
		return
	}

	svcID, err := strconv.Atoi(c.Param("svc_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Service ID in URL"})
		return
	}

	requester := c.GetString(middleware.UsernameKey)
	if err := h.userSvc.RemoveExtraService(userID, svcID, requester); err != nil {
		if errors.Is(err, service.ErrCannotModifyRoot) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Cannot modify root user services"})
		} else {
			log.Printf("[users] remove service failed for user %d and service %d: %v", userID, svcID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove service from user"})
		}
		return
	}

	log.Printf("[users] removed service %d from user %d", svcID, userID)
	c.String(http.StatusOK, "Service removed from user successfully")
}
