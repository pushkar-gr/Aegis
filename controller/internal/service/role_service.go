package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrRoleNameRequired = errors.New("role name is required")
	ErrRoleNameExists   = errors.New("role name already exists")
	ErrRoleProtected    = errors.New("forbidden: cannot delete root or admin")
	ErrRoleInUse        = errors.New("role is still assigned to one or more users")
)

// RoleService handles role management logic.
type RoleService interface {
	GetAll() ([]models.Role, error)
	Create(name, description string) (*models.Role, error)
	Delete(id int) error
	GetServices(roleID int) ([]models.Service, error)
	AddService(roleID, serviceID int) error
	RemoveService(roleID, svcID int) error
}

type roleService struct {
	roleRepo repository.RoleRepository
}

// NewRoleService creates a new RoleService.
func NewRoleService(roleRepo repository.RoleRepository) RoleService {
	return &roleService{roleRepo: roleRepo}
}

func (s *roleService) GetAll() ([]models.Role, error) {
	return s.roleRepo.GetAll()
}

func (s *roleService) Create(name, description string) (*models.Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrRoleNameRequired
	}
	id, err := s.roleRepo.Create(name, description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrRoleNameExists
		}
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	return &models.Role{Id: int(id), Name: name, Description: description}, nil
}

func (s *roleService) Delete(id int) error {
	targetRole, err := s.roleRepo.GetNameById(id)
	if err != nil {
		return err
	}
	if targetRole == "root" || targetRole == "admin" {
		return ErrRoleProtected
	}

	count, err := s.roleRepo.CountUsersWithRole(id)
	if err != nil {
		return fmt.Errorf("failed to check role usage: %w", err)
	}
	if count > 0 {
		return ErrRoleInUse
	}

	rows, err := s.roleRepo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if rows == 0 {
		return repository.ErrRoleNotFound
	}
	return nil
}

func (s *roleService) GetServices(roleID int) ([]models.Service, error) {
	return s.roleRepo.GetServices(roleID)
}

func (s *roleService) AddService(roleID, serviceID int) error {
	return s.roleRepo.AddService(roleID, serviceID)
}

func (s *roleService) RemoveService(roleID, svcID int) error {
	return s.roleRepo.RemoveService(roleID, svcID)
}
