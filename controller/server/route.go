package server

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

var jwtKey []byte

// init loads the JWT secret from environment variables on startup.
func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is required")
	}
	jwtKey = []byte(secret)
}

// StartServer configures and starts the TLS-enabled HTTP server.
func StartServer() {
	port := flag.String("port", ":443", "Server port")
	certFile := flag.String("cert", "/app/certs/server.crt", "Path to certificate file")
	keyFile := flag.String("key", "/app/certs/server.key", "Path to key file")

	flag.Parse()

	mux := http.NewServeMux()

	// --- Static Files ---
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/pages/login.html")
			return
		}
		http.NotFound(w, r)
	})

	// --- API Routes ---

	// 1. Authentication
	mux.HandleFunc("POST /api/auth/login", login)
	mux.Handle("POST /api/auth/logout", authMiddleware.ThenFunc(logout))
	mux.Handle("POST /api/auth/password", authMiddleware.ThenFunc(updatePassword))
	mux.Handle("GET /api/auth/me", authMiddleware.ThenFunc(getCurrentUser))

	// 2. Roles (RBAC)
	mux.Handle("GET /api/roles", adminOrRootOnly.ThenFunc(getRoles))
	mux.Handle("POST /api/roles", rootOnly.ThenFunc(createRole))
	mux.Handle("DELETE /api/roles/{id}", rootOnly.ThenFunc(deleteRole))
	mux.Handle("GET /api/roles/{id}/services", adminOrRootOnly.ThenFunc(getRoleServices))
	mux.Handle("POST /api/roles/{id}/services", adminOrRootOnly.ThenFunc(addRoleService))
	mux.Handle("DELETE /api/roles/{id}/services/{svc_id}", adminOrRootOnly.ThenFunc(removeRoleService))

	// 3. Services (Global Management)
	mux.Handle("GET /api/services", adminOrRootOnly.ThenFunc(getServices))
	mux.Handle("POST /api/services", adminOrRootOnly.ThenFunc(createService))
	mux.Handle("PUT /api/services/{id}", adminOrRootOnly.ThenFunc(updateService))
	mux.Handle("DELETE /api/services/{id}", adminOrRootOnly.ThenFunc(deleteService))

	// 4. User Management (Admin Panel)
	mux.Handle("GET /api/users", adminOrRootOnly.ThenFunc(getUsers))
	mux.Handle("POST /api/users", adminOrRootOnly.ThenFunc(createUser))
	mux.Handle("DELETE /api/users/{id}", adminOrRootOnly.ThenFunc(deleteUser))
	mux.Handle("PUT /api/users/{id}/role", adminOrRootOnly.ThenFunc(updateUserRole))
	mux.Handle("POST /api/users/{id}/reset-password", adminOrRootOnly.ThenFunc(resetUserPassword))
	mux.Handle("GET /api/users/{id}/services", adminOrRootOnly.ThenFunc(getUserServices))
	mux.Handle("POST /api/users/{id}/services", adminOrRootOnly.ThenFunc(addUserService))
	mux.Handle("DELETE /api/users/{id}/services/{svc_id}", adminOrRootOnly.ThenFunc(removeUserService))

	// 5. User Dashboard (Client)
	mux.Handle("GET /api/me/services", authMiddleware.ThenFunc(getMyServices))
	mux.Handle("GET /api/me/selected", authMiddleware.ThenFunc(getMyActiveServices))
	mux.Handle("POST /api/me/selected", authMiddleware.ThenFunc(selectActiveService))
	mux.Handle("DELETE /api/me/selected/{svc_id}", authMiddleware.ThenFunc(deselectActiveService))

	log.Printf("Server initializing on port %s...", *port)
	if err := http.ListenAndServeTLS(*port, *certFile, *keyFile, securityHeadersMiddleware(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
