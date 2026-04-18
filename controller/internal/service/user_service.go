package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"fmt"
	"regexp"
	"strings"
)

var usernameRE = regexp.MustCompile("^[a-zA-Z0-9_]{5,30}$")

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
}

// NewUserService creates a new UserService.
func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{userRepo: userRepo}
}

func (s *userService) checkRootProtectionByUserId(targetID int, requesterUsername string) error {
	targetRole, err := s.userRepo.GetRoleNameByUserID(targetID)
	if err != nil {
		return nil
	}

	return s.checkRootProtection(targetRole, requesterUsername)
}

func (s *userService) checkRootProtection(targetRole string, requesterUsername string) error {
	if targetRole == "root" {
		requesterRole, err := s.userRepo.GetRoleNameByUsername(requesterUsername)
		if err != nil {
			return fmt.Errorf("failed to verify requester role")
		}
		if requesterRole != "root" {
			return fmt.Errorf("forbidden: cannot modify root user")
		}
	}
	return nil
}

func (s *userService) GetAll() ([]models.User, error) {
	return s.userRepo.GetAll()
}

func (s *userService) Create(username, password string, roleID int, requesterUsername string) (*models.UserWithCredentials, error) {
	if requesterUsername != "" {
		targetRole, _ := s.userRepo.GetRoleNameByRoleId(roleID)
		if err := s.checkRootProtection(targetRole, requesterUsername); err != nil {
			return nil, err
		}
	}

	if !usernameRE.MatchString(username) {
		return nil, fmt.Errorf("invalid username format")
	}
	if err := utils.ValidatePasswordComplexity(password); err != nil {
		return nil, fmt.Errorf("password too weak: %w", err)
	}
	if roleID == 0 {
		return nil, fmt.Errorf("role_id is required")
	}

	hashedPwd, err := utils.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	id, err := s.userRepo.Create(username, hashedPwd, roleID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("username already exists")
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
		return fmt.Errorf("user not found")
	}
	return nil
}

func (s *userService) UpdateRole(id, roleID int, requesterUsername string) error {
	if requesterUsername != "" {
		if err := s.checkRootProtectionByUserId(id, requesterUsername); err != nil {
			return err
		}
	}

	targetRole, err := s.userRepo.GetRoleNameByUserID(roleID)
	if err != nil {
		return nil
	}
	if targetRole == "root" {
		return fmt.Errorf("forbidden: cannot become root user")
	}

	rows, err := s.userRepo.UpdateRole(id, roleID)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
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
		return fmt.Errorf("user not found")
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
