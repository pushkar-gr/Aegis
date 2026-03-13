package service

import (
	"Aegis/controller/internal/models"
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"Aegis/controller/proto"
	"fmt"
	"net"
	"strings"
	"time"
)

// ServiceService handles service management and dashboard logic.
type ServiceService interface {
	GetAll() ([]models.Service, error)
	Create(name, hostname, description string) (*models.Service, error)
	Update(id int, name, hostname, description string) (*models.Service, error)
	Delete(id int) error
	GetUserServices(userID, roleID int) ([]models.Service, error)
	GetUserActiveServices(userID int) ([]models.ActiveService, error)
	SelectActiveService(userID, roleID, serviceID int, clientIP string) error
	DeselectActiveService(userID, svcID int, clientIP string) error
}

type serviceService struct {
	svcRepo repository.ServiceRepository
}

// NewServiceService creates a new ServiceService.
func NewServiceService(svcRepo repository.ServiceRepository) ServiceService {
	return &serviceService{svcRepo: svcRepo}
}

// resolveHostnameAndPort parses host:port, resolves DNS, and returns IP and port.
func resolveHostnameAndPort(hostnameWithPort string) (uint32, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostnameWithPort)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hostname format '%s' (use hostname:port format): %w", hostnameWithPort, err)
	}

	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		resolvedIP = host
	} else {
		ips, err := utils.ResolveHostname(host)
		if err != nil || len(ips) == 0 {
			return 0, 0, fmt.Errorf("DNS resolution failed for hostname '%s': %w. Verify the hostname is correct and DNS is reachable", host, err)
		}
		resolvedIP = ips[0]
	}

	ipUint32 := utils.IpToUint32(resolvedIP)
	portNum, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port '%s': %w. Port must be a valid TCP port number (1-65535)", portStr, err)
	}
	return ipUint32, uint16(portNum), nil
}

func (s *serviceService) GetAll() ([]models.Service, error) {
	return s.svcRepo.GetAll()
}

func (s *serviceService) Create(name, hostname, description string) (*models.Service, error) {
	if name == "" || hostname == "" {
		return nil, fmt.Errorf("service name and hostname are required")
	}
	ip, port, err := resolveHostnameAndPort(hostname)
	if err != nil {
		return nil, err
	}

	id, err := s.svcRepo.Create(name, hostname, ip, port, description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("service name already exists")
		}
		return nil, fmt.Errorf("failed to create service: %w", err)
	}
	return &models.Service{Id: int(id), Name: name, Hostname: hostname, Ip: ip, Port: port, Description: description}, nil
}

func (s *serviceService) Update(id int, name, hostname, description string) (*models.Service, error) {
	if name == "" || hostname == "" {
		return nil, fmt.Errorf("service name and hostname are required")
	}
	ip, port, err := resolveHostnameAndPort(hostname)
	if err != nil {
		return nil, err
	}

	rows, err := s.svcRepo.Update(id, name, hostname, ip, port, description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("service name already exists")
		}
		return nil, fmt.Errorf("failed to update service: %w", err)
	}
	if rows == 0 {
		return nil, fmt.Errorf("service not found")
	}
	return &models.Service{Id: id, Name: name, Hostname: hostname, Ip: ip, Port: port, Description: description}, nil
}

func (s *serviceService) Delete(id int) error {
	rows, err := s.svcRepo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("service not found")
	}
	return nil
}

func (s *serviceService) GetUserServices(userID, roleID int) ([]models.Service, error) {
	return s.svcRepo.GetUserServices(userID, roleID)
}

func (s *serviceService) GetUserActiveServices(userID int) ([]models.ActiveService, error) {
	return s.svcRepo.GetUserActiveServices(userID)
}

func (s *serviceService) SelectActiveService(userID, roleID, serviceID int, clientIP string) error {
	hasAccess, err := s.svcRepo.CheckUserServiceAccess(userID, roleID, serviceID)
	if err != nil {
		return fmt.Errorf("permission check error: %w", err)
	}
	if !hasAccess {
		return fmt.Errorf("forbidden: no access to this service")
	}

	dstIP, dstPort, err := s.svcRepo.GetIPPort(serviceID)
	if err != nil {
		return fmt.Errorf("service not found or invalid configuration")
	}

	success, err := proto.SendSessionData(utils.IpToUint32(clientIP), dstIP, uint32(dstPort), true, time.Second)
	if err != nil {
		return fmt.Errorf("failed to activate session: %w", err)
	}
	if !success {
		return fmt.Errorf("session activation failed")
	}

	return s.svcRepo.InsertActiveService(userID, serviceID, 60)
}

func (s *serviceService) DeselectActiveService(userID, svcID int, clientIP string) error {
	dstIP, dstPort, err := s.svcRepo.GetIPPort(svcID)
	if err == nil {
		_, _ = proto.SendSessionData(utils.IpToUint32(clientIP), dstIP, uint32(dstPort), false, time.Second)
	}
	return s.svcRepo.DeleteActiveService(userID, svcID)
}
