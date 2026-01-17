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
	mux.HandleFunc("POST /api/auth/login", Login)
	mux.Handle("POST /api/auth/logout", AuthMiddleware(http.HandlerFunc(Logout), jwtKey))
	mux.Handle("POST /api/auth/password", AuthMiddleware(http.HandlerFunc(UpdatePassword), jwtKey))

	log.Printf("Server initializing on port %s...", *port)
	if err := http.ListenAndServeTLS(*port, *certFile, *keyFile, SecurityHeadersMiddleware(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
