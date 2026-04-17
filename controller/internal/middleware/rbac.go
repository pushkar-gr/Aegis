package middleware

import (
	"Aegis/controller/internal/repository"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole enforces role based access control.
func RequireRole(repo repository.UserRepository, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get(UsernameKey)
		if !exists {
			log.Printf("[middleware] rbac: user context missing")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		roleName, err := repo.GetRoleNameByUsername(username.(string))
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
