package repository

import (
	"database/sql"
	"errors"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func newErrTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestTranslateWriteErrorUnique(t *testing.T) {
	db := newErrTestDB(t)
	if _, err := db.Exec(`INSERT INTO items (name) VALUES ('a')`); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	_, err := db.Exec(`INSERT INTO items (name) VALUES ('a')`)
	got := translateWriteError(err)
	if !errors.Is(got, ErrDuplicate) {
		t.Errorf("expected ErrDuplicate, got %v", got)
	}
}

func TestTranslateWriteErrorPrimaryKey(t *testing.T) {
	db := newErrTestDB(t)
	if _, err := db.Exec(`INSERT INTO items (id, name) VALUES (1, 'a')`); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	_, err := db.Exec(`INSERT INTO items (id, name) VALUES (1, 'b')`)
	if !errors.Is(translateWriteError(err), ErrDuplicate) {
		t.Errorf("expected ErrDuplicate for primary key conflict, got %v", err)
	}
}

func TestTranslateWriteErrorPassesThroughOtherErrors(t *testing.T) {
	db := newErrTestDB(t)

	// NOT NULL violation is a constraint error, but not a duplicate.
	_, err := db.Exec(`INSERT INTO items (name) VALUES (NULL)`)
	got := translateWriteError(err)
	if errors.Is(got, ErrDuplicate) {
		t.Errorf("NOT NULL violation must not be reported as ErrDuplicate: %v", got)
	}
	if got == nil {
		t.Error("expected the original error to be preserved")
	}

	if translateWriteError(nil) != nil {
		t.Error("nil must stay nil")
	}
}

func TestErrNotFoundMatchesNoRows(t *testing.T) {
	db := newErrTestDB(t)
	var id int
	err := db.QueryRow(`SELECT id FROM items WHERE name = 'missing'`).Scan(&id)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
