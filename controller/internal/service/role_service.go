package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"fmt"
	"strings"
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
	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}
	id, err := s.roleRepo.Create(name, description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("role name already exists")
		}
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	return &models.Role{Id: int(id), Name: name, Description: description}, nil
}

func (s *roleService) Delete(id int) error {
	rows, err := s.roleRepo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("role not found")
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
