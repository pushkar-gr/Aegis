package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig holds JWT signing configuration.
type AuthConfig struct {
	JWTKey        []byte
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	TokenLifetime time.Duration
}

// LoginResult is used for successful Login.
type LoginResult struct {
	TokenString   string
	RefreshToken  string
	ExpiresAt     time.Time
	RefreshExpiry time.Time
	RoleName      string
}

// CurrentUserInfo is returned by GetCurrentUser.
type CurrentUserInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	RoleId   int    `json:"role_id"`
}

// TokenResult is used for RefreshToken.
type TokenResult struct {
	TokenString string
	ExpiresAt   time.Time
	RoleName    string
}

// AuthService handles authentication and token lifecycle.
type AuthService interface {
	Login(username, password string) (*LoginResult, error)
	Logout(username string) error
	UpdatePassword(username, oldPassword, newPassword string) error
	GetCurrentUser(username string) (*CurrentUserInfo, error)
	RefreshToken(token string) (*TokenResult, error)
	GenerateAccessToken(claims *models.Claims) (string, error)
}

type authService struct {
	userRepo repository.UserRepository
	cfg      AuthConfig
}

// NewAuthService creates a new AuthService.
func NewAuthService(userRepo repository.UserRepository, cfg AuthConfig) AuthService {
	return &authService{userRepo: userRepo, cfg: cfg}
}

func (s *authService) Login(username, password string) (*LoginResult, error) {
	storedHash, isActive, err := s.userRepo.GetCredentials(username)
	if err == sql.ErrNoRows {
		utils.CheckPasswordHash(password, "$2a$12$DUMMYHASH0000000000000000000000000000000000000000")
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if !utils.CheckPasswordHash(password, storedHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !isActive {
		return nil, fmt.Errorf("account disabled")
	}

	roleName, roleID, err := s.userRepo.GetRoleAndIDByUsername(username)
	if err != nil {
		log.Printf("[auth] failed to get role for user '%s': %v", username, err)
		roleID = 0
	}

	expiresAt := time.Now().Add(s.cfg.TokenLifetime)
	claims := &models.Claims{
		Username: username,
		Role:     roleName,
		RoleID:   roleID,
		Provider: "local",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    "aegis-controller",
			Subject:   username,
		},
	}

	tokenString, err := s.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("token generation error: %w", err)
	}

	refreshToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("refresh token generation error: %w", err)
	}

	userID, err := s.userRepo.GetIDByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
	if err := s.userRepo.CreateRefreshToken(refreshToken, userID, refreshExpiry); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &LoginResult{
		TokenString:   tokenString,
		RefreshToken:  refreshToken,
		ExpiresAt:     expiresAt,
		RefreshExpiry: refreshExpiry,
		RoleName:      roleName,
	}, nil
}

func (s *authService) Logout(username string) error {
	userID, err := s.userRepo.GetIDByUsername(username)
	if err != nil {
		return nil
	}
	return s.userRepo.DeleteUserRefreshTokens(userID)
}

func (s *authService) UpdatePassword(username, oldPassword, newPassword string) error {
	provider, err := s.userRepo.GetProvider(username)
	if err == nil && provider != "local" {
		return fmt.Errorf("password changes not allowed for SSO users")
	}

	if err := utils.ValidatePasswordComplexity(newPassword); err != nil {
		return fmt.Errorf("password too weak: %w", err)
	}

	storedHash, err := s.userRepo.GetPasswordHash(username)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if !utils.CheckPasswordHash(oldPassword, storedHash) {
		return fmt.Errorf("invalid credentials")
	}

	newHash, err := utils.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing error: %w", err)
	}

	rows, err := s.userRepo.UpdatePassword(username, newHash)
	if err != nil {
		return fmt.Errorf("update error: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (s *authService) GetCurrentUser(username string) (*CurrentUserInfo, error) {
	roleName, roleID, err := s.userRepo.GetRoleAndIDByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return &CurrentUserInfo{Username: username, Role: roleName, RoleId: roleID}, nil
}

func (s *authService) RefreshToken(token string) (*TokenResult, error) {
	userID, err := s.userRepo.GetRefreshToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	username, roleName, provider, roleID, isActive, err := s.userRepo.GetFullInfoByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if !isActive {
		return nil, fmt.Errorf("account disabled")
	}

	expiresAt := time.Now().Add(s.cfg.TokenLifetime)
	claims := &models.Claims{
		Username: username,
		Role:     roleName,
		RoleID:   roleID,
		Provider: provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    "aegis-controller",
			Subject:   username,
		},
	}

	tokenString, err := s.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("token generation error: %w", err)
	}

	return &TokenResult{
		TokenString: tokenString,
		ExpiresAt:   expiresAt,
		RoleName:    roleName,
	}, nil
}

func (s *authService) GenerateAccessToken(claims *models.Claims) (string, error) {
	if s.cfg.PrivateKey != nil {
		return utils.GenerateTokenRS256(claims, s.cfg.PrivateKey)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.cfg.JWTKey)
}
