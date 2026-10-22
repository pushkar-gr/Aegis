package middleware

import (
	"Aegis/controller/internal/repository"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole enforces role based access control.
func RequireRole(repo repository.UserRepository, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		usernameVal, exists := c.Get(UsernameKey)
		if !exists {
			log.Printf("[middleware] rbac: user context missing")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		username, ok := usernameVal.(string)
		if !ok || username == "" {
			log.Printf("[middleware] rbac: user context has unexpected type or is empty")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		roleName, err := repo.GetRoleNameByUsername(username)
		if errors.Is(err, repository.ErrNotFound) {
			log.Printf("[middleware] rbac: user '%s' no longer exists or has no role", username)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		if err != nil {
			log.Printf("[middleware] rbac: failed to get role for user '%s': %v", username, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		for _, r := range roles {
			if roleName == r {
				c.Next()
				return
			}
		}

		log.Printf("[middleware] rbac: access denied for user '%s' (role: %s)", username, roleName)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
	}
}
