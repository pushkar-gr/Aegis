package service

import "errors"

// Errors returned by the service layer. Handlers map these to HTTP responses
// with errors.Is; nothing should ever match on error text.

// Authentication.
var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountDisabled     = errors.New("account disabled")
	ErrSSOPasswordChange   = errors.New("password changes not allowed for SSO users")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
)

// Users.
var (
	ErrUserNotFound     = errors.New("user not found")
	ErrCannotModifyRoot = errors.New("forbidden: cannot modify root user")
	ErrCannotBecomeRoot = errors.New("forbidden: cannot become root user")
	ErrInvalidUsername  = errors.New("invalid username format")
	ErrRoleIDRequired   = errors.New("role_id is required")
	ErrUsernameExists   = errors.New("username already exists")
)

// Roles.
var (
	ErrRoleNotFound     = errors.New("role not found")
	ErrRoleNameRequired = errors.New("role name is required")
	ErrRoleNameExists   = errors.New("role name already exists")
	ErrRoleProtected    = errors.New("forbidden: cannot delete root or admin")
	ErrRoleInUse        = errors.New("role is still assigned to one or more users")
)

// Services and sessions.
var (
	ErrServiceNotFound      = errors.New("service not found")
	ErrServiceNameExists    = errors.New("service name already exists")
	ErrServiceInputRequired = errors.New("service name and hostname are required")
	ErrInvalidHostname      = errors.New("invalid hostname")
	ErrServiceAccessDenied  = errors.New("forbidden: no access to this service")
	ErrAgentUnavailable     = errors.New("agent unavailable")
	ErrAgentRejected        = errors.New("agent rejected the request")
)
