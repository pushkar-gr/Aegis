package repository

import (
	"Aegis/controller/internal/models"
	"database/sql"
	"fmt"
	"time"
)

// ActiveSessionSync represents data for synchronizing an active session.
type ActiveSessionSync struct {
	UserID    int
	ServiceID int
	TimeLeft  int
}

// HostnameSyncEntry holds service data for hostname-to-IP synchronisation.
type HostnameSyncEntry struct {
	ID          int
	Hostname    string
	CurrentIP   uint32
	CurrentPort uint16
}

// ServiceRepository defines all data access operations for services.
type ServiceRepository interface {
	GetAll() ([]models.Service, error)
	Create(name, hostname string, ip uint32, port uint16, description string) (int64, error)
	Update(id int, name, hostname string, ip uint32, port uint16, description string) (int64, error)
	Delete(id int) (int64, error)
	GetIPPort(id int) (uint32, uint16, error)
	GetServiceMap() (map[string]int, error)
	GetActiveServiceUsers() (map[int][]int, error)
	InsertActiveService(userID, serviceID, timeLeft int) error
	DeleteActiveService(userID, serviceID int) error
	SyncActiveSessions(sessions []ActiveSessionSync) error
	GetUserServices(userID, roleID int) ([]models.Service, error)
	GetUserActiveServices(userID int) ([]models.ActiveService, error)
	CheckUserServiceAccess(userID, roleID, serviceID int) (bool, error)
	ListForIPSync() ([]HostnameSyncEntry, error)
	UpdateIPPort(id int, ip uint32, port uint16) error
}

type serviceRepo struct {
	db                        *sql.DB
	stmtGetAll                *sql.Stmt
	stmtCreate                *sql.Stmt
	stmtDelete                *sql.Stmt
	stmtGetIPPort             *sql.Stmt
	stmtGetServiceMap         *sql.Stmt
	stmtGetActiveUsers        *sql.Stmt
	stmtInsertActive          *sql.Stmt
	stmtDeleteActive          *sql.Stmt
	stmtGetUserServices       *sql.Stmt
	stmtGetUserActiveServices *sql.Stmt
	stmtCheckAccess           *sql.Stmt
	stmtListForIPSync         *sql.Stmt
	stmtUpdateIPPort          *sql.Stmt
}

// NewServiceRepository prepares all statements and returns a ServiceRepository.
func NewServiceRepository(db *sql.DB) (ServiceRepository, error) {
	r := &serviceRepo{db: db}
	var err error

	queries := map[**sql.Stmt]string{
		&r.stmtGetAll:         "SELECT id, name, hostname, ip, port, description, created_at FROM services",
		&r.stmtCreate:         "INSERT INTO services (name, hostname, ip, port, description) VALUES (?, ?, ?, ?, ?)",
		&r.stmtDelete:         "DELETE FROM services WHERE id = ?",
		&r.stmtGetIPPort:      "SELECT ip, port FROM services WHERE id = ?",
		&r.stmtGetServiceMap:  "SELECT id, ip, port FROM services",
		&r.stmtGetActiveUsers: "SELECT user_id, service_id FROM user_active_services",
		&r.stmtInsertActive:   "INSERT OR REPLACE INTO user_active_services (user_id, service_id, updated_at, time_left) VALUES (?, ?, ?, ?)",
		&r.stmtDeleteActive:   "DELETE FROM user_active_services WHERE user_id = ? AND service_id = ?",
		&r.stmtGetUserServices: `SELECT s.id, s.name, s.hostname, s.ip, s.port, s.description, s.created_at
			FROM services s JOIN role_services rs ON s.id = rs.service_id WHERE rs.role_id = ?
			UNION
			SELECT s.id, s.name, s.hostname, s.ip, s.port, s.description, s.created_at
			FROM services s JOIN user_extra_services ues ON s.id = ues.service_id WHERE ues.user_id = ?`,
		&r.stmtGetUserActiveServices: `SELECT s.id, s.name, s.hostname, s.ip, s.port, s.description, s.created_at, uas.time_left, uas.updated_at
			FROM services s JOIN user_active_services uas ON s.id = uas.service_id
			WHERE uas.user_id = ? ORDER BY uas.updated_at DESC`,
		&r.stmtCheckAccess: `SELECT 1 FROM role_services WHERE role_id = ? AND service_id = ?
			UNION SELECT 1 FROM user_extra_services WHERE user_id = ? AND service_id = ?`,
		&r.stmtListForIPSync: "SELECT id, hostname, ip, port FROM services",
		&r.stmtUpdateIPPort:  "UPDATE services SET ip = ?, port = ? WHERE id = ?",
	}

	for stmt, query := range queries {
		*stmt, err = db.Prepare(query)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query %q: %w", query, err)
		}
	}
	return r, nil
}

func (r *serviceRepo) GetAll() ([]models.Service, error) {
	rows, err := r.stmtGetAll.Query()
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

func (r *serviceRepo) Create(name, hostname string, ip uint32, port uint16, description string) (int64, error) {
	res, err := r.stmtCreate.Exec(name, hostname, ip, port, description)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *serviceRepo) Update(id int, name, hostname string, ip uint32, port uint16, description string) (int64, error) {
	res, err := r.db.Exec(
		"UPDATE services SET name=?, hostname=?, ip=?, port=?, description=? WHERE id=?",
		name, hostname, ip, port, description, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *serviceRepo) Delete(id int) (int64, error) {
	res, err := r.stmtDelete.Exec(id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *serviceRepo) GetIPPort(id int) (uint32, uint16, error) {
	var ip uint32
	var port uint16
	err := r.stmtGetIPPort.QueryRow(id).Scan(&ip, &port)
	return ip, port, err
}

func (r *serviceRepo) GetServiceMap() (map[string]int, error) {
	rows, err := r.stmtGetServiceMap.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	svcMap := make(map[string]int)
	for rows.Next() {
		var id int
		var ip uint32
		var port uint16
		if err := rows.Scan(&id, &ip, &port); err != nil {
			continue
		}
		ipStr := fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
		key := fmt.Sprintf("%s:%d", ipStr, port)
		svcMap[key] = id
	}
	return svcMap, rows.Err()
}

func (r *serviceRepo) GetActiveServiceUsers() (map[int][]int, error) {
	rows, err := r.stmtGetActiveUsers.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := make(map[int][]int)
	for rows.Next() {
		var uID, sID int
		if err := rows.Scan(&uID, &sID); err != nil {
			continue
		}
		m[sID] = append(m[sID], uID)
	}
	return m, rows.Err()
}

func (r *serviceRepo) InsertActiveService(userID, serviceID, timeLeft int) error {
	_, err := r.stmtInsertActive.Exec(userID, serviceID, time.Now(), timeLeft)
	return err
}

func (r *serviceRepo) DeleteActiveService(userID, serviceID int) error {
	_, err := r.stmtDeleteActive.Exec(userID, serviceID)
	return err
}

func (r *serviceRepo) SyncActiveSessions(sessions []ActiveSessionSync) error {
	if len(sessions) == 0 {
		_, err := r.db.Exec("DELETE FROM user_active_services")
		return err
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.Exec("CREATE TEMP TABLE sync_sessions (user_id INTEGER, service_id INTEGER, time_left INTEGER)"); err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO sync_sessions (user_id, service_id, time_left) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, s := range sessions {
		if _, err := stmt.Exec(s.UserID, s.ServiceID, s.TimeLeft); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM user_active_services WHERE NOT EXISTS (
		SELECT 1 FROM sync_sessions WHERE sync_sessions.user_id = user_active_services.user_id
		AND sync_sessions.service_id = user_active_services.service_id)`); err != nil {
		return err
	}

	if _, err := tx.Exec(`UPDATE user_active_services SET
		time_left = (SELECT time_left FROM sync_sessions WHERE sync_sessions.user_id = user_active_services.user_id
			AND sync_sessions.service_id = user_active_services.service_id),
		updated_at = CURRENT_TIMESTAMP
		WHERE EXISTS (SELECT 1 FROM sync_sessions WHERE sync_sessions.user_id = user_active_services.user_id
			AND sync_sessions.service_id = user_active_services.service_id)`); err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT INTO user_active_services (user_id, service_id, time_left, updated_at)
		SELECT user_id, service_id, time_left, CURRENT_TIMESTAMP FROM sync_sessions
		WHERE NOT EXISTS (SELECT 1 FROM user_active_services
			WHERE user_active_services.user_id = sync_sessions.user_id
			AND user_active_services.service_id = sync_sessions.service_id)`); err != nil {
		return err
	}

	if _, err := tx.Exec("DROP TABLE sync_sessions"); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *serviceRepo) GetUserServices(userID, roleID int) ([]models.Service, error) {
	rows, err := r.stmtGetUserServices.Query(roleID, userID)
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

func (r *serviceRepo) GetUserActiveServices(userID int) ([]models.ActiveService, error) {
	rows, err := r.stmtGetUserActiveServices.Query(userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	services := make([]models.ActiveService, 0)
	for rows.Next() {
		var as models.ActiveService
		var desc sql.NullString
		if err := rows.Scan(&as.Id, &as.Name, &as.Hostname, &as.Ip, &as.Port, &desc, &as.CreatedAt, &as.TimeLeft, &as.UpdatedAt); err != nil {
			continue
		}
		as.Description = desc.String
		services = append(services, as)
	}
	return services, rows.Err()
}

func (r *serviceRepo) CheckUserServiceAccess(userID, roleID, serviceID int) (bool, error) {
	var exists int
	err := r.stmtCheckAccess.QueryRow(roleID, serviceID, userID, serviceID).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *serviceRepo) ListForIPSync() ([]HostnameSyncEntry, error) {
	rows, err := r.stmtListForIPSync.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var entries []HostnameSyncEntry
	for rows.Next() {
		var e HostnameSyncEntry
		if err := rows.Scan(&e.ID, &e.Hostname, &e.CurrentIP, &e.CurrentPort); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (r *serviceRepo) UpdateIPPort(id int, ip uint32, port uint16) error {
	_, err := r.stmtUpdateIPPort.Exec(ip, port, id)
	return err
}
