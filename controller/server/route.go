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

	// Register handlers.
	mux.HandleFunc("/login", Login)
	mux.Handle("/createuser", AuthMiddleware(http.HandlerFunc(CreateUser), jwtKey))
	mux.Handle("/welcome", AuthMiddleware(http.HandlerFunc(Welcome), jwtKey))
	mux.Handle("/logout", AuthMiddleware(http.HandlerFunc(Logout), jwtKey))

	log.Printf("Server initializing on port %s...", *port)
	if err := http.ListenAndServeTLS(*port, *certFile, *keyFile, SecurityHeadersMiddleware(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
