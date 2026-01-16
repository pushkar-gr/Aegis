package database

import (
	"Aegis/controller/internal/models"
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
	// createUserStmt is a prepared statement for inserting new users.
	createUserStmt *sql.Stmt
)

// InitDB initializes the database directory, opens the connection, sets performance pragmas,
// and ensures all necessary tables and seed data exist.
func InitDB() {
	var err error

	// Ensure the data directory exists.
	if _, err := os.Stat(DB_DIR); os.IsNotExist(err) {
		if err := os.Mkdir(DB_DIR, 0755); err != nil {
			log.Fatal("Failed to create data directory: ", err)
		}
	}
	dbPath := filepath.Join(DB_DIR, "aegis.db")

	// Open the SQLite database.
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal("Failed to open database: ", err)
	}

	// Enable Write-Ahead Logging (WAL) for better concurrency and performance.
	if _, err := DB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Println("Warning: Failed to enable WAL mode:", err)
	}

	// Configure connection pooling settings.
	DB.SetMaxOpenConns(1) // SQLite supports only one writer at a time.
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(time.Hour)

	// Enforce foreign key constraints.
	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Fatal("Failed to enable foreign keys: ", err)
	}

	// Create the roles table if it doesn't exist.
	createRolesTable := `
		CREATE TABLE IF NOT EXISTS roles (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" TEXT NOT NULL UNIQUE,
			"description" TEXT
		);`
	if _, err := DB.Exec(createRolesTable); err != nil {
		log.Fatal("Failed to create roles table: ", err)
	}

	// Seed default roles.
	seedRoles := `INSERT OR IGNORE INTO roles (name, description) VALUES 
		('admin', 'Administrator with full access'),
		('user', 'Standard user access');`

	if _, err := DB.Exec(seedRoles); err != nil {
		log.Fatal("Failed to seed roles: ", err)
	}

	// Create the users table if it doesn't exist.
	createUsersTable := `
		CREATE TABLE IF NOT EXISTS users (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"username" TEXT NOT NULL UNIQUE,
			"password" TEXT NOT NULL,
			"role_id" INTEGER NOT NULL DEFAULT 2,
			FOREIGN KEY(role_id) REFERENCES roles(id)
		);`

	_, err = DB.Exec(createUsersTable)
	if err != nil {
		log.Fatal("Failed to create users table: ", err)
	}

	// Prepare the user creation statement for reuse.
	createUserStmt, err = DB.Prepare(`
		INSERT INTO users (username, password, role_id) 
		VALUES (?, ?, (SELECT id FROM roles WHERE name = ?));`)
	if err != nil {
		log.Fatal("Failed to prepare create user statement: ", err)
	}

	log.Println("Database successfully initialized at", dbPath)
}

// CreateUser inserts a new user into the database with the specified credentials and role.
func CreateUser(user models.User) error {
	_, err := createUserStmt.Exec(user.Creds.Username, user.Creds.Password, user.Role)
	if err != nil {
		return err
	}
	return nil
}

// GetUser retrieves the credentials and role for a given username.
func GetUser(username string) (models.User, error) {
	var user models.User

	query := `
		SELECT u.username, u.password, r.name 
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		WHERE u.username = ?`

	err := DB.QueryRow(query, username).Scan(
		&user.Creds.Username,
		&user.Creds.Password,
		&user.Role,
	)

	if err != nil {
		return models.User{}, err
	}

	return user, nil
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
