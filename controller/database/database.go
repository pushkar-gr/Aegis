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

	log.Println("Database successfully initialized at", dbPath)
}

// GetRole retrieves the role name associated with a specific username.
func GetRole(username string) (string, error) {
	var role string

	query := `
		SELECT r.name
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.username = ?`

	err := DB.QueryRow(query, username).Scan(
		&role,
	)

	if err != nil {
		return "", err
	}

	return role, nil
}
