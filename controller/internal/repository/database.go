package repository

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB is the global database connection pool.
var DB *sql.DB

// InitDB opens the SQLite database, configures the connection pool, and returns the connection.
func InitDB(dir string, maxOpen, maxIdle int, connMaxLifetime time.Duration) *sql.DB {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Fatalf("[ERROR] [database] init failed: data directory '%s' does not exist", dir)
	}
	dbPath := filepath.Join(dir, "aegis.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("[ERROR] [database] init failed: aegis.db not found at %s", dbPath)
	}

	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("[ERROR] [database] init failed: %v", err)
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

	log.Printf("[INFO] [database] initialized successfully at %s", dbPath)
	return DB
}
