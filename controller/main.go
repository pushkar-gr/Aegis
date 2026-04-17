package main

import (
	"Aegis/controller/config"
	grpcPkg "Aegis/controller/internal/grpc"
	"Aegis/controller/internal/handler"
	"Aegis/controller/internal/middleware"
	"Aegis/controller/internal/oidc"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/router"
	"Aegis/controller/internal/service"
	"Aegis/controller/internal/watcher"
	"Aegis/controller/proto"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
)

func main() {
	cfg := config.Load()

	db := repository.InitDB(cfg.DBDir, cfg.MaxOpenConns, cfg.MaxIdleConns, cfg.ConnMaxLifetime)
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("[ERROR] Error closing database: %v", err)
		}
	}()

	userRepo, err := repository.NewUserRepository(db)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create user repository: %v", err)
	}
	roleRepo, err := repository.NewRoleRepository(db)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create role repository: %v", err)
	}
	svcRepo, err := repository.NewServiceRepository(db)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create service repository: %v", err)
	}

	privateKey, publicKey, err := loadRSAKeys(cfg.JwtPrivateKey, cfg.JwtPublicKey)
	if err != nil {
		log.Printf("[WARN] Failed to load RSA keys: %v. RS256 signing will not be available.", err)
		privateKey = nil
		publicKey = nil
	} else {
		log.Printf("[INFO] RSA keys loaded successfully for JWT RS256 signing")
	}

	authCfg := service.AuthConfig{
		JWTKey:        []byte(cfg.JwtKey),
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		TokenLifetime: cfg.JwtTokenLifetime,
	}

	authSvc := service.NewAuthService(userRepo, authCfg)
	userSvc := service.NewUserService(userRepo)
	roleSvc := service.NewRoleService(roleRepo)
	svcSvc := service.NewServiceService(svcRepo)

	authHandler := handler.NewAuthHandler(authSvc)
	userHandler := handler.NewUserHandler(userSvc)
	roleHandler := handler.NewRoleHandler(roleSvc)
	serviceHandler := handler.NewServiceHandler(svcSvc, userRepo)

	var oidcHandler *handler.OIDCHandler
	if cfg.OIDCEnabled {
		ctx := context.Background()
		oidcMgr, err := oidc.NewOIDCManager(
			ctx,
			cfg.OIDCGoogleClientID,
			cfg.OIDCGoogleSecret,
			cfg.OIDCGitHubClientID,
			cfg.OIDCGitHubSecret,
			cfg.OIDCRedirectURL,
			cfg.OIDCRoleMappingRules,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to initialize OIDC manager: %v", err)
		} else {
			log.Printf("[INFO] OIDC manager initialized successfully")
			oidcHandler = handler.NewOIDCHandler(oidcMgr, authSvc, userRepo, roleRepo)
		}
	}

	authMW := middleware.JWTAuth([]byte(cfg.JwtKey), publicKey)
	rootOnly := middleware.RequireRole(userRepo, "root")
	adminOrRoot := middleware.RequireRole(userRepo, "admin", "root")

	r := router.NewRouter(router.RouterConfig{
		AuthHandler:    authHandler,
		UserHandler:    userHandler,
		RoleHandler:    roleHandler,
		ServiceHandler: serviceHandler,
		OIDCHandler:    oidcHandler,
		AuthMiddleware: authMW,
		RootOnly:       rootOnly,
		AdminOrRoot:    adminOrRoot,
	})

	err = proto.Init(cfg.AgentAddress, cfg.AgentCertFile, cfg.AgentKeyFile, cfg.AgentCAFile, cfg.AgentServerName)
	if err != nil {
		log.Printf("[ERROR] Error starting grpc client: %v", err)
		return
	}

	grpcMgr := grpcPkg.NewSessionManager(svcRepo, userRepo)
	go grpcMgr.Start(grpcPkg.SessionConfig{IpUpdateInterval: cfg.IpUpdateInterval})

	go watcher.StartDockerWatcher()

	go func() {
		log.Printf("[INFO] Server initializing on port %s...", cfg.ServerPort)
		if err := r.RunTLS(cfg.ServerPort, cfg.CertFile, cfg.KeyFile); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("[INFO] Interrupt signal received. Shutting down server...")
}

func loadRSAKeys(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an RSA public key")
	}

	return privateKey, publicKey, nil
}
