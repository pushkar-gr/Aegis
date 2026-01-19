package database

import (
	"database/sql"
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
	stmtGetUserCredentials *sql.Stmt
	stmtGetUserIDAndRole   *sql.Stmt
	stmtUpdatePassword     *sql.Stmt
)

// InitDB sets up the database connection and prepares frequently used statements.
// This includes enabling WAL mode for better performance and preparing queries for login, user lookup, and password updates.
func InitDB() {
	var err error

	if _, err := os.Stat(DB_DIR); os.IsNotExist(err) {
		log.Fatalf("[database] init failed: data directory '%s' does not exist", DB_DIR)
	}
	dbPath := filepath.Join(DB_DIR, "aegis.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("[database] init failed: aegis.db not found at %s", dbPath)
	}

	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("[database] init failed: unable to open database: %v", err)
	}

	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Printf("[database] warning: WAL mode not enabled: %v", err)
	}

	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Fatalf("[database] init failed: unable to enable foreign keys: %v", err)
	}

	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(time.Hour)

	stmtGetUserCredentials, err = DB.Prepare("SELECT password, is_active FROM users WHERE username = ?")
	if err != nil {
		log.Fatalf("[database] init failed: unable to prepare user credentials query: %v", err)
	}

	stmtGetUserIDAndRole, err = DB.Prepare("SELECT id, role_id FROM users WHERE username = ?")
	if err != nil {
		log.Fatalf("[database] init failed: unable to prepare user ID query: %v", err)
	}

	stmtUpdatePassword, err = DB.Prepare("UPDATE users SET password = ? WHERE username = ?")
	if err != nil {
		log.Fatalf("[database] init failed: unable to prepare password update query: %v", err)
	}

	log.Printf("[database] initialized successfully at %s", dbPath)
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
