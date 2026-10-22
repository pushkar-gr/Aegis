package handler

import (
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/utils"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	authSvc service.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authSvc service.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login validates credentials and sets auth cookies.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[auth] login failed: invalid request body - %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	result, err := h.authSvc.Login(req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			log.Printf("[auth] login failed for user '%s': invalid credentials", req.Username)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		case errors.Is(err, service.ErrAccountDisabled):
			log.Printf("[auth] login failed for user '%s': account is inactive", req.Username)
			c.JSON(http.StatusForbidden, gin.H{"error": "Account is disabled"})
		default:
			log.Printf("[auth] login failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    result.TokenString,
		Expires:  result.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Expires:  result.RefreshExpiry,
		HttpOnly: true,
		Secure:   true,
		Path:     "/api/auth/refresh",
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("[auth] login successful for user '%s'", req.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully", "role": result.RoleName})
}

// Logout clears auth cookies and deletes refresh tokens.
func (h *AuthHandler) Logout(c *gin.Context) {
	username, _ := c.Get(middleware.UsernameKey)
	if u, ok := username.(string); ok && u != "" {
		if err := h.authSvc.Logout(u); err != nil {
			log.Printf("[auth] failed to delete refresh tokens for user '%s': %v", u, err)
		}
		log.Printf("[auth] user '%s' logged out", u)
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		Path:     "/api/auth/refresh",
		SameSite: http.SameSiteStrictMode,
	})
	c.String(http.StatusOK, "Logged out successfully")
}

// UpdatePassword changes the user's own password.
func (h *AuthHandler) UpdatePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	username, _ := c.Get(middleware.UsernameKey)
	u, _ := username.(string)

	if err := h.authSvc.UpdatePassword(u, req.OldPassword, req.NewPassword); err != nil {
		var policyErr *utils.PasswordPolicyError
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		case errors.Is(err, service.ErrSSOPasswordChange):
			c.JSON(http.StatusForbidden, gin.H{"error": "Password changes not allowed for SSO users"})
		case errors.As(err, &policyErr):
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password too weak: " + policyErr.Reason})
		default:
			log.Printf("[auth] password update failed for user '%s': %v", u, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	log.Printf("[auth] password updated successfully for user '%s'", u)
	c.String(http.StatusOK, "Password updated successfully")
}

// GetCurrentUser returns the current authenticated user's info.
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	username, ok := c.Get(middleware.UsernameKey)
	name, isString := username.(string)
	if !ok || !isString || name == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	info, err := h.authSvc.GetCurrentUser(name)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		log.Printf("[auth] get current user failed for '%s': %v", name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, info)
}

// RefreshToken generates a new access token from a valid refresh token.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing"})
		return
	}

	result, err := h.authSvc.RefreshToken(cookie)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRefreshToken), errors.Is(err, service.ErrAccountDisabled):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		default:
			log.Printf("[auth] refresh token failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    result.TokenString,
		Expires:  result.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Expires:  result.RefreshExpiry,
		HttpOnly: true,
		Secure:   true,
		Path:     "/api/auth/refresh",
		SameSite: http.SameSiteStrictMode,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully", "role": result.RoleName})
}
