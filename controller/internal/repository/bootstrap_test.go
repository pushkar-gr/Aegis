package repository

import (
	"Aegis/controller/internal/utils"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func newMigratedDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return openRaw(t, dbPath)
}

func TestEnsureRootUserGeneratesPassword(t *testing.T) {
	db := newMigratedDB(t)

	generated, created, err := EnsureRootUser(db, "")
	if err != nil {
		t.Fatalf("EnsureRootUser: %v", err)
	}
	if !created || generated == "" {
		t.Fatalf("expected a created user with a generated password, got created=%v generated=%q", created, generated)
	}

	hash := mustString(t, db, `SELECT password FROM users WHERE username = 'root'`)
	if !utils.CheckPasswordHash(generated, hash) {
		t.Error("stored hash does not match the generated password")
	}
	if role := mustString(t, db, `SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = 'root'`); role != "root" {
		t.Errorf("expected root role, got %q", role)
	}
}

func TestEnsureRootUserUsesConfiguredPassword(t *testing.T) {
	db := newMigratedDB(t)

	generated, created, err := EnsureRootUser(db, "Configured-Pass-1!")
	if err != nil || !created {
		t.Fatalf("EnsureRootUser: created=%v err=%v", created, err)
	}
	if generated != "" {
		t.Error("nothing should be reported as generated when a password is configured")
	}
	hash := mustString(t, db, `SELECT password FROM users WHERE username = 'root'`)
	if !utils.CheckPasswordHash("Configured-Pass-1!", hash) {
		t.Error("stored hash does not match the configured password")
	}
}

func TestEnsureRootUserLeavesExistingRootAlone(t *testing.T) {
	db := newMigratedDB(t)
	if _, _, err := EnsureRootUser(db, "First-Pass-1!"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	_, created, err := EnsureRootUser(db, "Other-Pass-1!")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created {
		t.Error("an existing root user must not be recreated")
	}
	hash := mustString(t, db, `SELECT password FROM users WHERE username = 'root'`)
	if !utils.CheckPasswordHash("First-Pass-1!", hash) {
		t.Error("the existing root password must not change")
	}
}

func TestEnsureRootUserNameTakenByNonRootUser(t *testing.T) {
	db := newMigratedDB(t)
	mustExec(t, db, `INSERT INTO users (username, password, role_id) VALUES ('root', 'x', 3)`)

	if _, _, err := EnsureRootUser(db, ""); err == nil {
		t.Fatal("expected an error when 'root' is taken by a non-root account")
	}
}
