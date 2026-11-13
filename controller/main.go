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
	"Aegis/controller/internal/utils"
	"Aegis/controller/internal/watcher"
	"Aegis/controller/proto"
	"context"
	"log"
	"os"
	"os/signal"
)

func main() {
	cfg := config.Load()

	if err := utils.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Fatalf("[ERROR] Invalid trusted proxy configuration: %v", err)
	}

	db, err := repository.InitDB(cfg.DBDir, cfg.MaxOpenConns, cfg.MaxIdleConns, cfg.ConnMaxLifetime)
	if err != nil {
		log.Fatalf("[FATAL] Database initialization failed: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("[ERROR] Error closing database: %v", err)
		}
	}()

	generatedRootPassword, created, err := repository.EnsureRootUser(db, cfg.RootPassword)
	if err != nil {
		log.Fatalf("[FATAL] Failed to create initial root user: %v", err)
	}
	if created {
		if generatedRootPassword != "" {
			log.Printf("[INFO] Created initial user 'root' with generated password: %s (shown only once, change it after first login)", generatedRootPassword)
		} else {
			log.Printf("[INFO] Created initial user 'root' with the password from AEGIS_ROOT_PASSWORD")
		}
	}

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

	authCfg := service.AuthConfig{
		JwtAlgorithm:  cfg.JwtAlgorithm,
		JWTKey:        []byte(cfg.JwtKey),
		TokenLifetime: cfg.JwtTokenLifetime,
	}

	var verifyToken utils.TokenVerifier
	if cfg.JwtAlgorithm == "RS256" {
		key, err := utils.LoadRSAPrivateKey(cfg.JwtPrivateKey)
		if err != nil {
			log.Fatalf("[FATAL] auth.jwt_algorithm=RS256 but key load failed: %v", err)
		}
		authCfg.PrivateKey = key
		authCfg.PublicKey = &key.PublicKey
		verifyToken = utils.NewRSAVerifier(authCfg.PublicKey)
	} else {
		verifyToken = utils.NewHMACVerifier(authCfg.JWTKey)
	}
	log.Printf("[INFO] JWT signing algorithm: %s", cfg.JwtAlgorithm)

	authSvc := service.NewAuthService(userRepo, authCfg)
	userSvc := service.NewUserService(userRepo, svcRepo)
	roleSvc := service.NewRoleService(roleRepo, svcRepo)
	svcSvc := service.NewServiceService(svcRepo, cfg.AgentCallTimeout)

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

	authMW := middleware.JWTAuth(verifyToken)
	optionalAuthMW := middleware.OptionalJWTAuth(verifyToken)
	rootOnly := middleware.RequireRole(userRepo, "root")
	adminOrRoot := middleware.RequireRole(userRepo, "admin", "root")

	r := router.NewRouter(router.RouterConfig{
		AuthHandler:            authHandler,
		UserHandler:            userHandler,
		RoleHandler:            roleHandler,
		ServiceHandler:         serviceHandler,
		OIDCHandler:            oidcHandler,
		AuthMiddleware:         authMW,
		OptionalAuthMiddleware: optionalAuthMW,
		RootOnly:               rootOnly,
		AdminOrRoot:            adminOrRoot,
	})

	err = proto.Init(cfg.AgentAddress, cfg.AgentCertFile, cfg.AgentKeyFile, cfg.AgentCAFile, cfg.AgentServerName)
	if err != nil {
		log.Printf("[ERROR] Error starting grpc client: %v", err)
		return
	}

	grpcMgr := grpcPkg.NewSessionManager(svcRepo, userRepo)
	go grpcMgr.Start(grpcPkg.SessionConfig{
		IpUpdateInterval:  cfg.IpUpdateInterval,
		AgentCallTimeout:  cfg.AgentCallTimeout,
		MonitorRetryDelay: cfg.MonitorRetryDelay,
	})

	go watcher.StartDockerWatcher(cfg.AgentCallTimeout)

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
