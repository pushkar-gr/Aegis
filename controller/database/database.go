package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const DB_DIR = "./data"

var (
	// DB is the global database connection pool.
	DB *sql.DB

	// Prepared statements for frequently used queries
	stmtGetUserCredentials     *sql.Stmt
	stmtGetUserIDAndRole       *sql.Stmt
	stmtUpdatePassword         *sql.Stmt
	stmtGetServiceMap          *sql.Stmt
	stmtGetActiveUsers         *sql.Stmt
	stmtGetServiceIPPort       *sql.Stmt
	stmtInsertActiveService    *sql.Stmt
	stmtDeleteActiveService    *sql.Stmt
	stmtCheckUserExists        *sql.Stmt
	stmtCheckServiceExists     *sql.Stmt
	stmtInsertRoleService      *sql.Stmt
	stmtDeleteRoleService      *sql.Stmt
	stmtInsertUserExtraService *sql.Stmt
	stmtDeleteUserExtraService *sql.Stmt
)

// ActiveSessionSync represents the data required to synchronize a session
type ActiveSessionSync struct {
	UserID    int
	ServiceID int
	TimeLeft  int
}

// InitDB sets up the database connection and prepares frequently used statements.
// This includes enabling WAL mode for better performance and preparing queries for login, user lookup, and password updates.
func InitDB(maxOpen, maxIdle int, connMaxLifetime time.Duration) {
	var err error

	if _, err := os.Stat(DB_DIR); os.IsNotExist(err) {
		log.Fatalf("[ERROR] [database] init failed: data directory '%s' does not exist", DB_DIR)
	}
	dbPath := filepath.Join(DB_DIR, "aegis.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("[ERROR] [database] init failed: aegis.db not found at %s", dbPath)
	}

	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("[ERROR] [database] init failed: unable to open database: %v", err)
	}

	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Printf("[WARN] [database] WAL mode not enabled: %v", err)
	}

	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Fatalf("[ERROR] [database] init failed: unable to enable foreign keys: %v", err)
	}

	DB.SetMaxOpenConns(maxOpen)
	DB.SetMaxIdleConns(maxIdle)
	DB.SetConnMaxLifetime(connMaxLifetime)

	if err := InitPreparedStatements(); err != nil {
		log.Fatalf("[ERROR] [database] init failed: unable to prepare statements: %v", err)
	}

	log.Printf("[INFO] [database] initialized successfully at %s", dbPath)
}

// InitPreparedStatements prepares frequently used SQL statements for reuse.
// This is exported for testing purposes.
func InitPreparedStatements() error {
	var err error

	stmtGetUserCredentials, err = DB.Prepare("SELECT password, is_active FROM users WHERE username = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare user credentials query: %w", err)
	}

	stmtGetUserIDAndRole, err = DB.Prepare("SELECT id, role_id FROM users WHERE username = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare user ID query: %w", err)
	}

	stmtUpdatePassword, err = DB.Prepare("UPDATE users SET password = ? WHERE username = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare password update query: %w", err)
	}

	stmtGetServiceMap, err = DB.Prepare("SELECT id, ip_port FROM services")
	if err != nil {
		return fmt.Errorf("failed to prepare service map query: %w", err)
	}

	stmtGetActiveUsers, err = DB.Prepare("SELECT user_id, service_id FROM user_active_services")
	if err != nil {
		return fmt.Errorf("failed to prepare active users query: %w", err)
	}

	stmtGetServiceIPPort, err = DB.Prepare("SELECT ip_port FROM services WHERE id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare service IP port query: %w", err)
	}

	stmtInsertActiveService, err = DB.Prepare("INSERT OR REPLACE INTO user_active_services (user_id, service_id, updated_at, time_left) VALUES (?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare insert active service query: %w", err)
	}

	stmtDeleteActiveService, err = DB.Prepare("DELETE FROM user_active_services WHERE user_id = ? AND service_id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare delete active service query: %w", err)
	}

	stmtCheckUserExists, err = DB.Prepare("SELECT id FROM users WHERE id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare check user exists query: %w", err)
	}

	stmtCheckServiceExists, err = DB.Prepare("SELECT id FROM services WHERE id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare check service exists query: %w", err)
	}

	stmtInsertRoleService, err = DB.Prepare("INSERT OR IGNORE INTO role_services (role_id, service_id) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare insert role service query: %w", err)
	}

	stmtDeleteRoleService, err = DB.Prepare("DELETE FROM role_services WHERE role_id = ? AND service_id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare delete role service query: %w", err)
	}

	stmtInsertUserExtraService, err = DB.Prepare("INSERT OR IGNORE INTO user_extra_services (user_id, service_id) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare insert user extra service query: %w", err)
	}

	stmtDeleteUserExtraService, err = DB.Prepare("DELETE FROM user_extra_services WHERE user_id = ? AND service_id = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare delete user extra service query: %w", err)
	}

	return nil
}

// GetUserCredentials fetches the password hash and active status for login authentication.
func GetUserCredentials(username string) (passwordHash string, isActive bool, err error) {
	err = stmtGetUserCredentials.QueryRow(username).Scan(&passwordHash, &isActive)
	return
}

// GetUserIDAndRole fetches the user ID and role ID for context resolution in requests.
func GetUserIDAndRole(username string) (id int, roleID int, err error) {
	err = stmtGetUserIDAndRole.QueryRow(username).Scan(&id, &roleID)
	return
}

// UpdateUserPassword changes a user's password hash and returns the number of affected rows.
func UpdateUserPassword(username, newPasswordHash string) (int64, error) {
	result, err := stmtUpdatePassword.Exec(newPasswordHash, username)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetPasswordHash retrieves the password hash for verifying the current password.
func GetPasswordHash(username string) (string, error) {
	var hash string
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hash)
	return hash, err
}

// SyncActiveSessions performs a bulk update of the user_active_services table.
// This function efficiently synchronizes the active sessions by:
// 1. Inserting/updating sessions from the provided list
// 2. Removing stale sessions not in the provided list
func SyncActiveSessions(sessions []ActiveSessionSync) error {
	if len(sessions) == 0 {
		// If no sessions, delete all active sessions
		_, err := DB.Exec("DELETE FROM user_active_services")
		return err
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Load the provided session list into a temporary table
	_, err = tx.Exec("CREATE TEMP TABLE sync_sessions (user_id INTEGER, service_id INTEGER, time_left INTEGER)")
	if err != nil {
		return err
	}

	// Use bulk insert for better performance
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

	// Remove records from the main table that are not in the temp table (stale sessions)
	deleteQuery := `
		DELETE FROM user_active_services
		WHERE NOT EXISTS (
			SELECT 1 FROM sync_sessions
			WHERE sync_sessions.user_id = user_active_services.user_id 
			AND sync_sessions.service_id = user_active_services.service_id
		)
	`
	if _, err := tx.Exec(deleteQuery); err != nil {
		return err
	}

	// Update existing records in the main table using data from the temp table
	updateQuery := `
		UPDATE user_active_services
		SET 
			time_left = (SELECT time_left FROM sync_sessions WHERE sync_sessions.user_id = user_active_services.user_id AND sync_sessions.service_id = user_active_services.service_id),
			updated_at = CURRENT_TIMESTAMP
		WHERE EXISTS (
			SELECT 1 FROM sync_sessions 
			WHERE sync_sessions.user_id = user_active_services.user_id 
			AND sync_sessions.service_id = user_active_services.service_id
		)
	`
	if _, err := tx.Exec(updateQuery); err != nil {
		return err
	}

	// Insert new records that don't exist in the main table
	insertQuery := `
		INSERT INTO user_active_services (user_id, service_id, time_left, updated_at)
		SELECT user_id, service_id, time_left, CURRENT_TIMESTAMP
		FROM sync_sessions
		WHERE NOT EXISTS (
			SELECT 1 FROM user_active_services
			WHERE user_active_services.user_id = sync_sessions.user_id
			AND user_active_services.service_id = sync_sessions.service_id
		)
	`
	if _, err := tx.Exec(insertQuery); err != nil {
		return err
	}

	// Cleanup
	if _, err := tx.Exec("DROP TABLE sync_sessions"); err != nil {
		return err
	}

	return tx.Commit()
}

// GetServiceMap returns a map of "ip:port" -> service_id for all services.
func GetServiceMap() (map[string]int, error) {
	rows, err := stmtGetServiceMap.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	svcMap := make(map[string]int)
	for rows.Next() {
		var id int
		var ipPort string
		if err := rows.Scan(&id, &ipPort); err == nil {
			svcMap[ipPort] = id
		}
	}
	return svcMap, nil
}

// GetActiveServiceUsers returns a map of service_id -> []user_id for currently active sessions in DB.
func GetActiveServiceUsers() (map[int][]int, error) {
	rows, err := stmtGetActiveUsers.Query()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	activeMap := make(map[int][]int)
	for rows.Next() {
		var uID, sID int
		if err := rows.Scan(&uID, &sID); err == nil {
			activeMap[sID] = append(activeMap[sID], uID)
		}
	}
	return activeMap, nil
}

// GetServiceIPPort retrieves the IP:port string for a service ID.
func GetServiceIPPort(serviceID int) (string, error) {
	var ipPort string
	err := stmtGetServiceIPPort.QueryRow(serviceID).Scan(&ipPort)
	return ipPort, err
}

// InsertActiveService adds or updates an active service session.
func InsertActiveService(userID, serviceID, timeLeft int) error {
	_, err := stmtInsertActiveService.Exec(userID, serviceID, time.Now(), timeLeft)
	return err
}

// DeleteActiveService removes an active service session.
func DeleteActiveService(userID, serviceID int) error {
	_, err := stmtDeleteActiveService.Exec(userID, serviceID)
	return err
}

// CheckUserExists verifies if a user ID exists in the database.
func CheckUserExists(userID int) (bool, error) {
	var id int
	err := stmtCheckUserExists.QueryRow(userID).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// CheckServiceExists verifies if a service ID exists in the database.
func CheckServiceExists(serviceID int) (bool, error) {
	var id int
	err := stmtCheckServiceExists.QueryRow(serviceID).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// InsertRoleService adds a service to a role.
func InsertRoleService(roleID, serviceID int) error {
	_, err := stmtInsertRoleService.Exec(roleID, serviceID)
	return err
}

// DeleteRoleService removes a service from a role.
func DeleteRoleService(roleID, serviceID int) error {
	_, err := stmtDeleteRoleService.Exec(roleID, serviceID)
	return err
}

// InsertUserExtraService adds an extra service to a user.
func InsertUserExtraService(userID, serviceID int) error {
	_, err := stmtInsertUserExtraService.Exec(userID, serviceID)
	return err
}

// DeleteUserExtraService removes an extra service from a user.
func DeleteUserExtraService(userID, serviceID int) error {
	_, err := stmtDeleteUserExtraService.Exec(userID, serviceID)
	return err
}
