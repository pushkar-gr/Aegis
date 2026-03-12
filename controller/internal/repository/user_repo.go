package repository

import (
	"Aegis/controller/internal/models"
	"database/sql"
	"fmt"
	"time"
)

// UserRepository defines all data access operations for users.
type UserRepository interface {
	GetCredentials(username string) (hash string, isActive bool, err error)
	GetIDAndRole(username string) (id, roleID int, err error)
	UpdatePassword(username, newHash string) (int64, error)
	GetPasswordHash(username string) (string, error)
	GetAll() ([]models.User, error)
	Create(username, hashedPwd string, roleID int) (int64, error)
	Delete(id int) (int64, error)
	GetRoleNameByUserID(id int) (string, error)
	GetRoleNameByUsername(username string) (string, error)
	UpdateRole(id, roleID int) (int64, error)
	ResetPassword(id int, newHash string) (int64, error)
	GetExtraServices(userID int) ([]models.Service, error)
	AddExtraService(userID, serviceID int) error
	RemoveExtraService(userID, serviceID int) error
	CreateRefreshToken(token string, userID int, expiresAt time.Time) error
	GetRefreshToken(token string) (userID int, err error)
	DeleteRefreshToken(token string) error
	DeleteUserRefreshTokens(userID int) error
	CleanupExpiredRefreshTokens() error
	GetByProviderAndID(provider, providerID string) (*models.User, error)
	CreateOIDCUser(username, provider, providerID, email string, roleID int) (*models.User, error)
	UpdateEmail(id int, email string) error
	GetFullInfoByID(userID int) (username, roleName, provider string, roleID int, isActive bool, err error)
	GetIDByUsername(username string) (int, error)
	GetProvider(username string) (string, error)
	GetRoleAndIDByUsername(username string) (roleName string, roleID int, err error)
}

type userRepo struct {
	db                          *sql.DB
	stmtGetCredentials          *sql.Stmt
	stmtGetIDAndRole            *sql.Stmt
	stmtUpdatePassword          *sql.Stmt
	stmtGetPasswordHash         *sql.Stmt
	stmtGetAll                  *sql.Stmt
	stmtCreate                  *sql.Stmt
	stmtDelete                  *sql.Stmt
	stmtGetRoleNameByUserID     *sql.Stmt
	stmtGetRoleNameByUsername   *sql.Stmt
	stmtUpdateRole              *sql.Stmt
	stmtResetPassword           *sql.Stmt
	stmtGetExtraServices        *sql.Stmt
	stmtAddExtraService         *sql.Stmt
	stmtRemoveExtraService      *sql.Stmt
	stmtCreateRefreshToken      *sql.Stmt
	stmtGetRefreshToken         *sql.Stmt
	stmtDeleteRefreshToken      *sql.Stmt
	stmtDeleteUserRefreshTokens *sql.Stmt
	stmtGetByProviderAndID      *sql.Stmt
	stmtGetFullInfoByID         *sql.Stmt
	stmtGetIDByUsername         *sql.Stmt
	stmtGetProvider             *sql.Stmt
	stmtGetRoleAndID            *sql.Stmt
}

// NewUserRepository prepares all statements and returns a UserRepository.
func NewUserRepository(db *sql.DB) (UserRepository, error) {
	r := &userRepo{db: db}
	var err error

	queries := map[**sql.Stmt]string{
		&r.stmtGetCredentials:          "SELECT password, is_active FROM users WHERE username = ?",
		&r.stmtGetIDAndRole:            "SELECT id, role_id FROM users WHERE username = ?",
		&r.stmtUpdatePassword:          "UPDATE users SET password = ? WHERE username = ?",
		&r.stmtGetPasswordHash:         "SELECT password FROM users WHERE username = ?",
		&r.stmtGetAll:                  "SELECT id, username, role_id, is_active FROM users",
		&r.stmtCreate:                  "INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)",
		&r.stmtDelete:                  "DELETE FROM users WHERE id = ?",
		&r.stmtGetRoleNameByUserID:     "SELECT r.name FROM users u INNER JOIN roles r ON u.role_id = r.id WHERE u.id = ?",
		&r.stmtGetRoleNameByUsername:   "SELECT r.name FROM users u INNER JOIN roles r ON u.role_id = r.id WHERE u.username = ?",
		&r.stmtUpdateRole:              "UPDATE users SET role_id = ? WHERE id = ?",
		&r.stmtResetPassword:           "UPDATE users SET password = ? WHERE id = ?",
		&r.stmtGetExtraServices:        "SELECT s.id, s.name, s.hostname, s.ip, s.port, s.description, s.created_at FROM services s JOIN user_extra_services ues ON s.id = ues.service_id WHERE ues.user_id = ?",
		&r.stmtAddExtraService:         "INSERT OR IGNORE INTO user_extra_services (user_id, service_id) VALUES (?, ?)",
		&r.stmtRemoveExtraService:      "DELETE FROM user_extra_services WHERE user_id = ? AND service_id = ?",
		&r.stmtCreateRefreshToken:      "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
		&r.stmtGetRefreshToken:         "SELECT user_id FROM refresh_tokens WHERE token = ? AND expires_at > ?",
		&r.stmtDeleteRefreshToken:      "DELETE FROM refresh_tokens WHERE token = ?",
		&r.stmtDeleteUserRefreshTokens: "DELETE FROM refresh_tokens WHERE user_id = ?",
		&r.stmtGetByProviderAndID:      "SELECT id, username, role_id, is_active, provider, provider_id FROM users WHERE provider = ? AND provider_id = ?",
		&r.stmtGetFullInfoByID:         "SELECT u.username, r.name, r.id, u.is_active, COALESCE(u.provider, 'local') FROM users u INNER JOIN roles r ON u.role_id = r.id WHERE u.id = ?",
		&r.stmtGetIDByUsername:         "SELECT id FROM users WHERE username = ?",
		&r.stmtGetProvider:             "SELECT COALESCE(provider, 'local') FROM users WHERE username = ?",
		&r.stmtGetRoleAndID:            "SELECT r.name, r.id FROM users u INNER JOIN roles r ON u.role_id = r.id WHERE u.username = ?",
	}

	for stmt, query := range queries {
		*stmt, err = db.Prepare(query)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query %q: %w", query, err)
		}
	}
	return r, nil
}

func (r *userRepo) GetCredentials(username string) (string, bool, error) {
	var hash string
	var isActive bool
	err := r.stmtGetCredentials.QueryRow(username).Scan(&hash, &isActive)
	return hash, isActive, err
}

func (r *userRepo) GetIDAndRole(username string) (int, int, error) {
	var id, roleID int
	err := r.stmtGetIDAndRole.QueryRow(username).Scan(&id, &roleID)
	return id, roleID, err
}

func (r *userRepo) UpdatePassword(username, newHash string) (int64, error) {
	res, err := r.stmtUpdatePassword.Exec(newHash, username)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *userRepo) GetPasswordHash(username string) (string, error) {
	var hash string
	err := r.stmtGetPasswordHash.QueryRow(username).Scan(&hash)
	return hash, err
}

func (r *userRepo) GetAll() ([]models.User, error) {
	rows, err := r.stmtGetAll.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	users := make([]models.User, 0)
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.Id, &u.Username, &u.RoleId, &u.IsActive); err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *userRepo) Create(username, hashedPwd string, roleID int) (int64, error) {
	res, err := r.stmtCreate.Exec(username, hashedPwd, roleID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *userRepo) Delete(id int) (int64, error) {
	res, err := r.stmtDelete.Exec(id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *userRepo) GetRoleNameByUserID(id int) (string, error) {
	var name string
	err := r.stmtGetRoleNameByUserID.QueryRow(id).Scan(&name)
	return name, err
}

func (r *userRepo) GetRoleNameByUsername(username string) (string, error) {
	var name string
	err := r.stmtGetRoleNameByUsername.QueryRow(username).Scan(&name)
	return name, err
}

func (r *userRepo) UpdateRole(id, roleID int) (int64, error) {
	res, err := r.stmtUpdateRole.Exec(roleID, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *userRepo) ResetPassword(id int, newHash string) (int64, error) {
	res, err := r.stmtResetPassword.Exec(newHash, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *userRepo) GetExtraServices(userID int) ([]models.Service, error) {
	rows, err := r.stmtGetExtraServices.Query(userID)
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

func (r *userRepo) AddExtraService(userID, serviceID int) error {
	_, err := r.stmtAddExtraService.Exec(userID, serviceID)
	return err
}

func (r *userRepo) RemoveExtraService(userID, serviceID int) error {
	_, err := r.stmtRemoveExtraService.Exec(userID, serviceID)
	return err
}

func (r *userRepo) CreateRefreshToken(token string, userID int, expiresAt time.Time) error {
	_, err := r.stmtCreateRefreshToken.Exec(token, userID, expiresAt)
	return err
}

func (r *userRepo) GetRefreshToken(token string) (int, error) {
	var userID int
	err := r.stmtGetRefreshToken.QueryRow(token, time.Now()).Scan(&userID)
	return userID, err
}

func (r *userRepo) DeleteRefreshToken(token string) error {
	_, err := r.stmtDeleteRefreshToken.Exec(token)
	return err
}

func (r *userRepo) DeleteUserRefreshTokens(userID int) error {
	_, err := r.stmtDeleteUserRefreshTokens.Exec(userID)
	return err
}

func (r *userRepo) CleanupExpiredRefreshTokens() error {
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE expires_at <= CURRENT_TIMESTAMP")
	return err
}

func (r *userRepo) GetByProviderAndID(provider, providerID string) (*models.User, error) {
	var u models.User
	err := r.stmtGetByProviderAndID.QueryRow(provider, providerID).Scan(
		&u.Id, &u.Username, &u.RoleId, &u.IsActive, &u.Provider, &u.ProviderID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *userRepo) CreateOIDCUser(username, provider, providerID, email string, roleID int) (*models.User, error) {
	res, err := r.db.Exec(
		"INSERT INTO users (username, password, role_id, is_active, provider, provider_id, email) VALUES (?, NULL, ?, 1, ?, ?, ?)",
		username, roleID, provider, providerID, email)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.User{
		Id:         int(id),
		Username:   username,
		RoleId:     roleID,
		IsActive:   true,
		Provider:   provider,
		ProviderID: providerID,
	}, nil
}

func (r *userRepo) UpdateEmail(id int, email string) error {
	_, err := r.db.Exec("UPDATE users SET email = ? WHERE id = ?", email, id)
	return err
}

func (r *userRepo) GetFullInfoByID(userID int) (string, string, string, int, bool, error) {
	var username, roleName, provider string
	var roleID int
	var isActive bool
	err := r.stmtGetFullInfoByID.QueryRow(userID).Scan(&username, &roleName, &roleID, &isActive, &provider)
	return username, roleName, provider, roleID, isActive, err
}

func (r *userRepo) GetIDByUsername(username string) (int, error) {
	var id int
	err := r.stmtGetIDByUsername.QueryRow(username).Scan(&id)
	return id, err
}

func (r *userRepo) GetProvider(username string) (string, error) {
	var provider string
	err := r.stmtGetProvider.QueryRow(username).Scan(&provider)
	return provider, err
}

func (r *userRepo) GetRoleAndIDByUsername(username string) (string, int, error) {
	var roleName string
	var roleID int
	err := r.stmtGetRoleAndID.QueryRow(username).Scan(&roleName, &roleID)
	return roleName, roleID, err
}
