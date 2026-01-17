package database

import (
	"Aegis/controller/internal/utils"
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

	createTables()
	seedRoles()
	seedRootUser()

	log.Println("Database successfully initialized at", dbPath)
}

func createTables() {
	// 1. Roles table
	createRolesTable := `
	CREATE TABLE IF NOT EXISTS roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT
	);`
	if _, err := DB.Exec(createRolesTable); err != nil {
		log.Fatal("Failed to create roles table:", err)
	}

	// 2. Services table
	createServicesTable := `
	CREATE TABLE IF NOT EXISTS services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip_port TEXT NOT NULL,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := DB.Exec(createServicesTable); err != nil {
		log.Fatal("Failed to create services table:", err)
	}

	// 3. Users table
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role_id INTEGER,
		is_active BOOLEAN DEFAULT 1,
		FOREIGN KEY(role_id) REFERENCES roles(id)
	);`
	if _, err := DB.Exec(createUsersTable); err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// 4. Role Services (Many-to-Many: Base permissions for a role)
	createRoleServicesTable := `
	CREATE TABLE IF NOT EXISTS role_services (
		role_id INTEGER,
		service_id INTEGER,
		PRIMARY KEY (role_id, service_id),
		FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
		FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
	);`
	if _, err := DB.Exec(createRoleServicesTable); err != nil {
		log.Fatal("Failed to create role_services table:", err)
	}

	// 5. User Extra Services (Many-to-Many: Specific extra permissions for a user)
	createUserExtraServicesTable := `
	CREATE TABLE IF NOT EXISTS user_extra_services (
		user_id INTEGER,
		service_id INTEGER,
		PRIMARY KEY (user_id, service_id),
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
	);`
	if _, err := DB.Exec(createUserExtraServicesTable); err != nil {
		log.Fatal("Failed to create user_extra_services table:", err)
	}

	// 6. User Active Services (Many-to-Many: Services the user has currently "Selected")
	createUserActiveServicesTable := `
	CREATE TABLE IF NOT EXISTS user_active_services (
		user_id INTEGER,
		service_id INTEGER,
		PRIMARY KEY (user_id, service_id),
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
	);`
	if _, err := DB.Exec(createUserActiveServicesTable); err != nil {
		log.Fatal("Failed to create user_active_services table:", err)
	}
}

func seedRoles() {
	// Seed default roles if they don't exist
	roles := []struct {
		Name        string
		Description string
	}{
		{"root", "Super Administrator with full access"},
		{"admin", "Administrator with management access"},
		{"user", "Standard user"},
	}

	for _, role := range roles {
		_, err := DB.Exec("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", role.Name, role.Description)
		if err != nil {
			log.Printf("Failed to seed role %s: %v", role.Name, err)
		}
	}
}

func seedRootUser() {
	// Check if root user exists
	var exists bool
	err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = 'root')").Scan(&exists)
	if err != nil {
		log.Println("Error checking for root user:", err)
		return
	}

	if !exists {
		// Find root role ID
		var roleID int
		err = DB.QueryRow("SELECT id FROM roles WHERE name = 'root'").Scan(&roleID)
		if err != nil {
			log.Println("Error finding root role ID:", err)
			return
		}

		// Create root user with default password 'root'
		password := "root"
		hashedPassword, err := utils.HashPassword(password)
		if err != nil {
			log.Printf("Failed to hash root password: %v", err)
			return
		}

		_, err = DB.Exec("INSERT INTO users (username, password, role_id, is_active) VALUES (?, ?, ?, ?)", "root", hashedPassword, roleID, true)
		if err != nil {
			log.Printf("Failed to seed root user: %v", err)
		} else {
			log.Println("Seeded root user with password 'root'")
		}
	}
}
