package router

import (
	"Aegis/controller/internal/handler"
	internalMiddleware "Aegis/controller/internal/middleware"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RouterConfig holds all handlers and middleware for setting up routes.
type RouterConfig struct {
	AuthHandler    *handler.AuthHandler
	UserHandler    *handler.UserHandler
	RoleHandler    *handler.RoleHandler
	ServiceHandler *handler.ServiceHandler
	OIDCHandler    *handler.OIDCHandler
	AuthMiddleware gin.HandlerFunc
	RootOnly       gin.HandlerFunc
	AdminOrRoot    gin.HandlerFunc
}

// NewRouter builds and returns the configured Gin router.
func NewRouter(cfg RouterConfig) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(internalMiddleware.SecurityHeaders())

	r.StaticFS("/static", http.Dir("static"))
	r.GET("/", func(c *gin.Context) {
		c.File("static/pages/login.html")
	})

	api := r.Group("/api")

	auth := api.Group("/auth")
	{
		auth.POST("/login", cfg.AuthHandler.Login)
		auth.POST("/logout", cfg.AuthMiddleware, cfg.AuthHandler.Logout)
		auth.POST("/password", cfg.AuthMiddleware, cfg.AuthHandler.UpdatePassword)
		auth.GET("/me", cfg.AuthMiddleware, cfg.AuthHandler.GetCurrentUser)
		auth.POST("/refresh", cfg.AuthHandler.RefreshToken)

		if cfg.OIDCHandler != nil {
			oidc := auth.Group("/oidc")
			oidc.GET("/providers", cfg.OIDCHandler.ListProviders)
			oidc.GET("/login", cfg.OIDCHandler.Login)
			oidc.GET("/callback", cfg.OIDCHandler.Callback)
		}
	}

	roles := api.Group("/roles")
	roles.Use(cfg.AuthMiddleware)
	{
		roles.GET("", cfg.AdminOrRoot, cfg.RoleHandler.GetAll)
		roles.POST("", cfg.RootOnly, cfg.RoleHandler.Create)
		roles.DELETE("/:id", cfg.RootOnly, cfg.RoleHandler.Delete)
		roles.GET("/:id/services", cfg.AdminOrRoot, cfg.RoleHandler.GetServices)
		roles.POST("/:id/services", cfg.AdminOrRoot, cfg.RoleHandler.AddService)
		roles.DELETE("/:id/services/:svc_id", cfg.AdminOrRoot, cfg.RoleHandler.RemoveService)
	}

	services := api.Group("/services")
	services.Use(cfg.AuthMiddleware, cfg.AdminOrRoot)
	{
		services.GET("", cfg.ServiceHandler.GetAll)
		services.POST("", cfg.ServiceHandler.Create)
		services.PUT("/:id", cfg.ServiceHandler.Update)
		services.DELETE("/:id", cfg.ServiceHandler.Delete)
	}

	users := api.Group("/users")
	users.Use(cfg.AuthMiddleware, cfg.AdminOrRoot)
	{
		users.GET("", cfg.UserHandler.GetAll)
		users.POST("", cfg.UserHandler.Create)
		users.DELETE("/:id", cfg.UserHandler.Delete)
		users.PUT("/:id/role", cfg.UserHandler.UpdateRole)
		users.POST("/:id/reset-password", cfg.UserHandler.ResetPassword)
		users.GET("/:id/services", cfg.UserHandler.GetServices)
		users.POST("/:id/services", cfg.UserHandler.AddService)
		users.DELETE("/:id/services/:svc_id", cfg.UserHandler.RemoveService)
	}

	me := api.Group("/me")
	me.Use(cfg.AuthMiddleware)
	{
		me.GET("/services", cfg.ServiceHandler.GetMyServices)
		me.GET("/selected", cfg.ServiceHandler.GetMyActiveServices)
		me.POST("/selected", cfg.ServiceHandler.SelectActiveService)
		me.DELETE("/selected/:svc_id", cfg.ServiceHandler.DeselectActiveService)
	}

	return r
}
