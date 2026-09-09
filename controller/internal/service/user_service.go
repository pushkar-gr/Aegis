package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var usernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrCannotModifyRoot = errors.New("forbidden: cannot modify root user")
	ErrCannotBecomeRoot = errors.New("forbidden: cannot become root user")
	ErrInvalidUsername  = errors.New("invalid username format")
	ErrRoleIDRequired   = errors.New("role_id is required")
	ErrInvalidRole      = errors.New("role does not exist")
	ErrUsernameExists   = errors.New("username already exists")
)

// UserService handles user management logic.
type UserService interface {
	GetAll() ([]models.User, error)
	Create(username, password string, roleID int, requesterUsername string) (*models.UserWithCredentials, error)
	Delete(id int, requesterUsername string) error
	UpdateRole(id, roleID int, requesterUsername string) error
	ResetPassword(id int, newPassword, requesterUsername string) error
	GetExtraServices(userID int) ([]models.Service, error)
	AddExtraService(userID, serviceID int, requesterUsername string) error
	RemoveExtraService(userID, svcID int, requesterUsername string) error
}

type userService struct {
	userRepo repository.UserRepository
	svcRepo  repository.ServiceRepository
}

// NewUserService creates a new UserService.
func NewUserService(userRepo repository.UserRepository, svcRepo repository.ServiceRepository) UserService {
	return &userService{userRepo: userRepo, svcRepo: svcRepo}
}

func (s *userService) checkRootProtectionByUserId(targetID int, requesterUsername string) error {
	targetRole, err := s.userRepo.GetRoleNameByUserID(targetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("failed to verify target user role: %w", err)
	}
	return s.checkRootProtection(targetRole, requesterUsername)
}

func (s *userService) checkRootProtection(targetRole string, requesterUsername string) error {
	if targetRole == "root" {
		requesterRole, err := s.userRepo.GetRoleNameByUsername(requesterUsername)
		if err != nil {
			return fmt.Errorf("failed to verify requester role: %w", err)
		}
		if requesterRole != "root" {
			return ErrCannotModifyRoot
		}
	}
	return nil
}

func (s *userService) GetAll() ([]models.User, error) {
	return s.userRepo.GetAll()
}

func (s *userService) Create(username, password string, roleID int, requesterUsername string) (*models.UserWithCredentials, error) {
	if roleID == 0 {
		return nil, ErrRoleIDRequired
	}

	targetRoleName, err := s.userRepo.GetRoleNameByRoleId(roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidRole
		}
		return nil, fmt.Errorf("failed to verify role: %w", err)
	}

	if requesterUsername != "" {
		if err := s.checkRootProtection(targetRoleName, requesterUsername); err != nil {
			return nil, err
		}
	}

	if !usernameRE.MatchString(username) {
		return nil, ErrInvalidUsername
	}
	if err := utils.ValidatePasswordComplexity(password); err != nil {
		return nil, fmt.Errorf("password too weak: %w", err)
	}

	hashedPwd, err := utils.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	id, err := s.userRepo.Create(username, hashedPwd, roleID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUsernameExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &models.UserWithCredentials{
		Id:          int(id),
		RoleId:      roleID,
		Credentials: models.Credentials{Username: username},
	}, nil
}

func (s *userService) Delete(id int, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(id, requesterUsername); err != nil {
			return err
		}
	}
	rows, err := s.userRepo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *userService) UpdateRole(id, roleID int, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(id, requesterUsername); err != nil {
			return err
		}
	}

	targetRoleName, err := s.userRepo.GetRoleNameByRoleId(roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidRole
		}
		return fmt.Errorf("failed to verify target role: %w", err)
	}
	if targetRoleName == "root" {
		return ErrCannotBecomeRoot
	}

	rows, err := s.userRepo.UpdateRole(id, roleID)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *userService) ResetPassword(id int, newPassword, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(id, requesterUsername); err != nil {
			return err
		}
	}
	if err := utils.ValidatePasswordComplexity(newPassword); err != nil {
		return fmt.Errorf("password too weak: %w", err)
	}
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing error: %w", err)
	}
	rows, err := s.userRepo.ResetPassword(id, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *userService) GetExtraServices(userID int) ([]models.Service, error) {
	return s.userRepo.GetExtraServices(userID)
}

func (s *userService) AddExtraService(userID, serviceID int, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(userID, requesterUsername); err != nil {
			return err
		}
	}

	userExists, err := s.userRepo.Exists(userID)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	}
	if !userExists {
		return ErrUserNotFound
	}

	svcExists, err := s.svcRepo.Exists(serviceID)
	if err != nil {
		return fmt.Errorf("failed to check service existence: %w", err)
	}
	if !svcExists {
		return ErrServiceNotFound
	}

	return s.userRepo.AddExtraService(userID, serviceID)
}

func (s *userService) RemoveExtraService(userID, svcID int, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(userID, requesterUsername); err != nil {
			return err
		}
	}
	return s.userRepo.RemoveExtraService(userID, svcID)
}
