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

// InitDB initializes the database directory, opens the connection, sets performance pragmas,
// and ensures all necessary tables and seed data exist.
func InitDB() {
	var err error

	// Ensure the data directory exists.
	if _, err := os.Stat(DB_DIR); os.IsNotExist(err) {
		log.Fatal("Error: Database directory './data' does not exist. Please create it.")
	}
	dbPath := filepath.Join(DB_DIR, "aegis.db")

	// 2. Check for Database File
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatal("Error: 'aegis.db' not found. Please download it from the repo.")
	}

	// Open the SQLite database.
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal("Failed to open database: ", err)
	}

	// Enable Write-Ahead Logging (WAL) for better concurrency and performance.
	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Println("Warning: Failed to enable WAL mode:", err)
	}

	// Enforce foreign key constraints.
	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Fatal("Failed to enable foreign keys: ", err)
	}

	// Configure connection pooling settings.
	DB.SetMaxOpenConns(1) // SQLite supports only one writer at a time.
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(time.Hour)

	// Prepare frequently used statements
	stmtGetUserCredentials, err = DB.Prepare("SELECT password, is_active FROM users WHERE username = ?")
	if err != nil {
		log.Fatal("Failed to prepare stmtGetUserCredentials: ", err)
	}

	stmtGetUserIDAndRole, err = DB.Prepare("SELECT id, role_id FROM users WHERE username = ?")
	if err != nil {
		log.Fatal("Failed to prepare stmtGetUserIDAndRole: ", err)
	}

	stmtUpdatePassword, err = DB.Prepare("UPDATE users SET password = ? WHERE username = ?")
	if err != nil {
		log.Fatal("Failed to prepare stmtUpdatePassword: ", err)
	}

	log.Println("Database successfully initialized at", dbPath)
}

// GetUserCredentials retrieves password hash and active status for a user.
// Used during login authentication.
func GetUserCredentials(username string) (passwordHash string, isActive bool, err error) {
	err = stmtGetUserCredentials.QueryRow(username).Scan(&passwordHash, &isActive)
	return
}

// GetUserIDAndRole retrieves user ID and role ID for a given username.
// Used in dashboard and user context resolution.
func GetUserIDAndRole(username string) (id int, roleID int, err error) {
	err = stmtGetUserIDAndRole.QueryRow(username).Scan(&id, &roleID)
	return
}

// UpdateUserPassword updates a user's password hash.
// Used in password change operations.
func UpdateUserPassword(username, newPasswordHash string) (int64, error) {
	result, err := stmtUpdatePassword.Exec(newPasswordHash, username)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetPasswordHash retrieves only the password hash for a user.
// Used in password verification operations.
func GetPasswordHash(username string) (string, error) {
	var hash string
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hash)
	return hash, err
}
