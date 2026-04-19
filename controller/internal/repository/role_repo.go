package repository

import (
	"Aegis/controller/internal/models"
	"database/sql"
	"fmt"
)

// RoleRepository defines all data access operations for roles.
type RoleRepository interface {
	GetAll() ([]models.Role, error)
	Create(name, description string) (int64, error)
	Delete(id int) (int64, error)
	GetServices(roleID int) ([]models.Service, error)
	AddService(roleID, serviceID int) error
	RemoveService(roleID, serviceID int) error
	GetIDByName(name string) (int, error)
	GetNameById(id int) (string, error)
}

type roleRepo struct {
	db                *sql.DB
	stmtGetAll        *sql.Stmt
	stmtCreate        *sql.Stmt
	stmtDelete        *sql.Stmt
	stmtGetServices   *sql.Stmt
	stmtAddService    *sql.Stmt
	stmtRemoveService *sql.Stmt
	stmtGetIDByName   *sql.Stmt
	stmtGetNameById   *sql.Stmt
}

// NewRoleRepository prepares all statements and returns RoleRepository.
func NewRoleRepository(db *sql.DB) (RoleRepository, error) {
	r := &roleRepo{db: db}
	var err error

	queries := map[**sql.Stmt]string{
		&r.stmtGetAll:        "SELECT id, name, description FROM roles",
		&r.stmtCreate:        "INSERT INTO roles (name, description) VALUES (?, ?)",
		&r.stmtDelete:        "DELETE FROM roles WHERE id = ?",
		&r.stmtGetServices:   "SELECT s.id, s.name, s.hostname, s.ip, s.port, s.description, s.created_at FROM services s INNER JOIN role_services rs ON s.id = rs.service_id WHERE rs.role_id = ?",
		&r.stmtAddService:    "INSERT OR IGNORE INTO role_services (role_id, service_id) VALUES (?, ?)",
		&r.stmtRemoveService: "DELETE FROM role_services WHERE role_id = ? AND service_id = ?",
		&r.stmtGetIDByName:   "SELECT id FROM roles WHERE name = ?",
		&r.stmtGetNameById:   "SELECT name FROM roles WHERE id = ?",
	}

	for stmt, query := range queries {
		*stmt, err = db.Prepare(query)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query %q: %w", query, err)
		}
	}
	return r, nil
}

func (r *roleRepo) GetAll() ([]models.Role, error) {
	rows, err := r.stmtGetAll.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	roles := make([]models.Role, 0)
	for rows.Next() {
		var role models.Role
		var desc sql.NullString
		if err := rows.Scan(&role.Id, &role.Name, &desc); err != nil {
			continue
		}
		role.Description = desc.String
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *roleRepo) Create(name, description string) (int64, error) {
	res, err := r.stmtCreate.Exec(name, description)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *roleRepo) Delete(id int) (int64, error) {
	res, err := r.stmtDelete.Exec(id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *roleRepo) GetServices(roleID int) ([]models.Service, error) {
	rows, err := r.stmtGetServices.Query(roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	services := make([]models.Service, 0)
	for rows.Next() {
		var s models.Service
		var desc sql.NullString
		if err := rows.Scan(&s.Id, &s.Name, &s.Hostname, &s.Ip, &s.Port, &desc, &s.CreatedAt); err != nil {
			continue
		}
		s.Description = desc.String
		services = append(services, s)
	}
	return services, rows.Err()
}

func (r *roleRepo) AddService(roleID, serviceID int) error {
	_, err := r.stmtAddService.Exec(roleID, serviceID)
	return err
}

func (r *roleRepo) RemoveService(roleID, serviceID int) error {
	_, err := r.stmtRemoveService.Exec(roleID, serviceID)
	return err
}

func (r *roleRepo) GetIDByName(name string) (int, error) {
	var id int
	err := r.stmtGetIDByName.QueryRow(name).Scan(&id)
	return id, err
}

func (r *roleRepo) GetNameById(id int) (string, error) {
	var name string
	err := r.stmtGetNameById.QueryRow(id).Scan(&name)
	return name, err
}
