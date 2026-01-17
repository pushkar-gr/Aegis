package server

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

// init loads the JWT secret from environment variables on startup.
func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is required")
	} else {
		jwtKey = []byte(secret)
	}
}

// StartServer configures and starts the TLS-enabled HTTP server.
func StartServer() {
	port := flag.String("port", ":443", "Server port")
	certFile := flag.String("cert", "/app/certs/server.crt", "Path to certificate file")
	keyFile := flag.String("key", "/app/certs/server.key", "Path to key file")

	flag.Parse()

	mux := http.NewServeMux()

	// --- API Routes ---

	// 1. Authentication
	mux.HandleFunc("POST /api/auth/login", login)
	mux.Handle("POST /api/auth/logout", authMiddleware.ThenFunc(logout))
	mux.Handle("POST /api/auth/password", authMiddleware.ThenFunc(updatePassword))

	// 2. Roles (RBAC)
	mux.Handle("GET /api/roles", adminOrRootOnly.ThenFunc(getRoles))
	mux.Handle("POST /api/roles", rootOnly.ThenFunc(createRole))
	mux.Handle("DELETE /api/roles/{id}", rootOnly.ThenFunc(deleteRole))
	mux.Handle("POST /api/roles/{id}/services", adminOrRootOnly.ThenFunc(addRoleService))
	mux.Handle("DELETE /api/roles/{id}/services/{svc_id}", adminOrRootOnly.ThenFunc(removeRoleService))

	log.Printf("Server initializing on port %s...", *port)
	if err := http.ListenAndServeTLS(*port, *certFile, *keyFile, securityHeadersMiddleware(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
