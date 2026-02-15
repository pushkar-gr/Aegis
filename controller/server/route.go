package server

import (
	"Aegis/controller/internal/oidc"
	"crypto/rsa"
	"log"
	"net/http"
	"time"
)

var jwtKey []byte
var jwtTokenLifetime time.Duration
var jwtPrivateKey *rsa.PrivateKey
var jwtPublicKey *rsa.PublicKey
var oidcManager *oidc.OIDCManager

// StartServer configures and starts the TLS-enabled HTTP server.
func StartServer(port, certFile, keyFile string, jwtKeyByte []byte, jwtTokenLifetimeDuration time.Duration, privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, oidcMgr *oidc.OIDCManager) {
	jwtKey = jwtKeyByte
	jwtTokenLifetime = jwtTokenLifetimeDuration
	jwtPrivateKey = privKey
	jwtPublicKey = pubKey
	oidcManager = oidcMgr

	mux := http.NewServeMux()

	// Static files
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/pages/login.html")
			return
		}
		http.NotFound(w, r)
	})

	// API routes

	// Authentication
	mux.HandleFunc("POST /api/auth/login", login)
	mux.Handle("POST /api/auth/logout", authMiddleware.ThenFunc(logout))
	mux.Handle("POST /api/auth/password", authMiddleware.ThenFunc(updatePassword))
	mux.Handle("GET /api/auth/me", authMiddleware.ThenFunc(getCurrentUser))

	// OIDC Authentication
	if oidcManager != nil {
		mux.HandleFunc("GET /api/auth/oidc/providers", listOIDCProviders)
		mux.HandleFunc("GET /api/auth/oidc/login", oidcLogin)
		mux.HandleFunc("GET /api/auth/oidc/callback", oidcCallback)
	}

	// Roles (RBAC)
	mux.Handle("GET /api/roles", adminOrRootOnly.ThenFunc(getRoles))
	mux.Handle("POST /api/roles", rootOnly.ThenFunc(createRole))
	mux.Handle("DELETE /api/roles/{id}", rootOnly.ThenFunc(deleteRole))
	mux.Handle("GET /api/roles/{id}/services", adminOrRootOnly.ThenFunc(getRoleServices))
	mux.Handle("POST /api/roles/{id}/services", adminOrRootOnly.ThenFunc(addRoleService))
	mux.Handle("DELETE /api/roles/{id}/services/{svc_id}", adminOrRootOnly.ThenFunc(removeRoleService))

	// Services (global management)
	mux.Handle("GET /api/services", adminOrRootOnly.ThenFunc(getServices))
	mux.Handle("POST /api/services", adminOrRootOnly.ThenFunc(createService))
	mux.Handle("PUT /api/services/{id}", adminOrRootOnly.ThenFunc(updateService))
	mux.Handle("DELETE /api/services/{id}", adminOrRootOnly.ThenFunc(deleteService))

	// User management (admin panel)
	mux.Handle("GET /api/users", adminOrRootOnly.ThenFunc(getUsers))
	mux.Handle("POST /api/users", adminOrRootOnly.ThenFunc(createUser))
	mux.Handle("DELETE /api/users/{id}", adminOrRootOnly.ThenFunc(deleteUser))
	mux.Handle("PUT /api/users/{id}/role", adminOrRootOnly.ThenFunc(updateUserRole))
	mux.Handle("POST /api/users/{id}/reset-password", adminOrRootOnly.ThenFunc(resetUserPassword))
	mux.Handle("GET /api/users/{id}/services", adminOrRootOnly.ThenFunc(getUserServices))
	mux.Handle("POST /api/users/{id}/services", adminOrRootOnly.ThenFunc(addUserService))
	mux.Handle("DELETE /api/users/{id}/services/{svc_id}", adminOrRootOnly.ThenFunc(removeUserService))

	// User dashboard (client)
	mux.Handle("GET /api/me/services", authMiddleware.ThenFunc(getMyServices))
	mux.Handle("GET /api/me/selected", authMiddleware.ThenFunc(getMyActiveServices))
	mux.Handle("POST /api/me/selected", authMiddleware.ThenFunc(selectActiveService))
	mux.Handle("DELETE /api/me/selected/{svc_id}", authMiddleware.ThenFunc(deselectActiveService))

	log.Printf("[INFO] Server initializing on port %s...", port)
	if err := http.ListenAndServeTLS(port, certFile, keyFile, securityHeadersMiddleware(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
