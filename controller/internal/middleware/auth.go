package middleware

import (
	"Aegis/controller/internal/utils"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Gin context key to store the username.
const UsernameKey = "username"

// JWTAuth validates the JWT token cookie and sets the username in Gin context.
func JWTAuth(verify utils.TokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			log.Printf("[middleware] auth failed: missing token cookie: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication cookie missing"})
			return
		}
		username, err := verify(cookie)
		if err != nil {
			log.Printf("[middleware] auth failed: token invalid - %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.Set(UsernameKey, username)
		c.Next()
	}
}

// OptionalJWTAuth is like JWTAuth but does not aborts the request.
func OptionalJWTAuth(verify utils.TokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cookie, err := c.Cookie("token"); err == nil {
			if username, err := verify(cookie); err == nil {
				c.Set(UsernameKey, username)
			}
		}
		c.Next()
	}
}
