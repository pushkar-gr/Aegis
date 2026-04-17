package middleware

import (
	"Aegis/controller/internal/utils"
	"crypto/rsa"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Gin context key to store the username.
const UsernameKey = "username"

// JWTAuth validates the JWT token cookie and sets the username in Gin context.
func JWTAuth(jwtKey []byte, publicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			log.Printf("[middleware] auth failed: missing token cookie: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication cookie missing"})
			return
		}

		var username string
		if publicKey != nil {
			username, err = utils.GetUsernameFromTokenRS256(cookie, publicKey)
		} else {
			username, err = utils.GetUsernameFromToken(cookie, jwtKey)
		}

		if err != nil {
			log.Printf("[middleware] auth failed: token invalid - %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Set(UsernameKey, username)
		c.Next()
	}
}

// SecurityHeaders adds security HTTP headers to all responses.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		c.Next()
	}
}
