package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DBFileName is the name of the SQLite database file inside the data directory.
const DBFileName = "aegis.db"

// DB is the global database connection pool.
var DB *sql.DB

func sqliteDSN(path string, params map[string]string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}
	return u.String(), nil
}

// InitDB prepares the data directory by applies pending schema migrations.
func InitDB(dir string, maxOpen, maxIdle int, connMaxLifetime time.Duration) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory %q: %w", dir, err)
	}
	dbPath := filepath.Join(dir, DBFileName)

	if err := Migrate(context.Background(), dbPath); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	dsn, err := sqliteDSN(dbPath, map[string]string{
		"_foreign_keys": "on",
		"_busy_timeout": "5000",
		"_journal_mode": "WAL",
		"_synchronous":  "NORMAL",
	})
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	DB = db
	log.Printf("[INFO] [database] initialized successfully at %s", dbPath)
	return db, nil
}
