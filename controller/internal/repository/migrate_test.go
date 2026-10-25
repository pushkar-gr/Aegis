package repository

import (
	"Aegis/controller/migrations"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

const latestVersion = 8

func openRawFK(t *testing.T, path, foreignKeys string) *sql.DB {
	t.Helper()
	dsn, err := sqliteDSN(path, map[string]string{"_foreign_keys": foreignKeys})
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// openRaw opens the database with foreign keys enforced, like the application.
func openRaw(t *testing.T, path string) *sql.DB { return openRawFK(t, path, "on") }

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func mustCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func mustString(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	var s string
	if err := db.QueryRow(query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	return mustCount(t, db, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
}

func backupFiles(t *testing.T, dbPath string) []string {
	t.Helper()
	matches, err := filepath.Glob(dbPath + ".pre-migration-*.bak")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return matches
}

func ipInt(a, b, c, d int) int { return a<<24 | b<<16 | c<<8 | d }

// schemaSignature describes every table's columns, foreign keys and indexes
// in a form that can be compared between two databases.
func schemaSignature(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()
	tables, err := listTables(ctx, db)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	delete(tables, versionTable)

	var names []string
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []string
	for _, table := range names {
		var parts []string

		rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
		if err != nil {
			t.Fatalf("table_info: %v", err)
		}
		for rows.Next() {
			var cid, notNull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
				t.Fatalf("scan: %v", err)
			}
			parts = append(parts, fmt.Sprintf("col %d %s %s notnull=%d dflt=%s pk=%d", cid, name, strings.ToUpper(ctype), notNull, dflt.String, pk))
		}
		_ = rows.Close()

		rows, err = db.Query(fmt.Sprintf(`PRAGMA foreign_key_list(%q)`, table))
		if err != nil {
			t.Fatalf("foreign_key_list: %v", err)
		}
		for rows.Next() {
			var id, seq int
			var parent, from, to, onUpdate, onDelete, match string
			if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				t.Fatalf("scan: %v", err)
			}
			parts = append(parts, fmt.Sprintf("fk %s->%s.%s delete=%s", from, parent, to, onDelete))
		}
		_ = rows.Close()

		rows, err = db.Query(fmt.Sprintf(`PRAGMA index_list(%q)`, table))
		if err != nil {
			t.Fatalf("index_list: %v", err)
		}
		type idx struct {
			name            string
			unique, partial int
		}
		var idxs []idx
		for rows.Next() {
			var seq, unique, partial int
			var name, origin string
			if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
				t.Fatalf("scan: %v", err)
			}
			if origin == "c" { // explicitly created (not for PK/UNIQUE constraints)
				idxs = append(idxs, idx{name, unique, partial})
			}
		}
		_ = rows.Close()
		for _, ix := range idxs {
			var cols []string
			rows, err = db.Query(fmt.Sprintf(`PRAGMA index_info(%q)`, ix.name))
			if err != nil {
				t.Fatalf("index_info: %v", err)
			}
			for rows.Next() {
				var seqno, cid int
				var name string
				if err := rows.Scan(&seqno, &cid, &name); err != nil {
					t.Fatalf("scan: %v", err)
				}
				cols = append(cols, name)
			}
			_ = rows.Close()
			parts = append(parts, fmt.Sprintf("index %s(%s) unique=%d partial=%d", ix.name, strings.Join(cols, ","), ix.unique, ix.partial))
		}
		// CHECK constraints are only visible in the table SQL.
		var ddl string
		_ = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name = ?`, table).Scan(&ddl)
		parts = append(parts, fmt.Sprintf("checks=%d", strings.Count(strings.ToUpper(ddl), "CHECK (")))

		sort.Strings(parts)
		out = append(out, table+":\n  "+strings.Join(parts, "\n  "))
	}
	return strings.Join(out, "\n")
}

const fxRoles = `CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);`

const fxLinkTables = `
CREATE TABLE role_services (
    role_id INTEGER, service_id INTEGER, PRIMARY KEY (role_id, service_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE user_extra_services (
    user_id INTEGER, service_id INTEGER, PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE user_active_services (
    user_id INTEGER NOT NULL, service_id INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, time_left INTEGER DEFAULT 60,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);`

const fxUsersV10 = `CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);`

const fxUsersV12 = `CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT,
    role_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    provider TEXT DEFAULT 'local',
    provider_id TEXT,
    email TEXT,
    FOREIGN KEY(role_id) REFERENCES roles(id)
);
CREATE INDEX idx_users_provider_id ON users(provider, provider_id);
CREATE INDEX idx_users_email ON users(email);
CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);`

const (
	fxServicesV10 = `CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ip_port TEXT NOT NULL,
    description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`
	fxServicesV11 = `CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ip_port TEXT NOT NULL,
    description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    hostname TEXT NOT NULL DEFAULT 'static-placeholder-hostname');`
	fxServicesV111 = `CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, hostname TEXT NOT NULL,
    ip INTEGER NOT NULL, port INTEGER NOT NULL, description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`
)

func buildLegacyDB(t *testing.T, path, version string) {
	t.Helper()
	db := openRawFK(t, path, "off")

	mustExec(t, db, fxRoles)
	switch version {
	case "v1.0", "v1.1", "v1.1.1":
		mustExec(t, db, fxUsersV10)
	case "v1.2":
		mustExec(t, db, fxUsersV12)
	}
	switch version {
	case "v1.0":
		mustExec(t, db, fxServicesV10)
	case "v1.1":
		mustExec(t, db, fxServicesV11)
	default:
		mustExec(t, db, fxServicesV111)
	}
	mustExec(t, db, fxLinkTables)

	mustExec(t, db, `INSERT INTO roles (id, name, description) VALUES (1,'root','r'),(2,'admin','a'),(3,'user','u')`)
	mustExec(t, db, `INSERT INTO users (id, username, password, role_id, is_active) VALUES (1,'root','hash',1,1),(2,'alice','hash',3,1)`)

	web, dbIP := ipInt(10, 0, 0, 5), ipInt(192, 168, 1, 10)
	switch version {
	case "v1.0":
		mustExec(t, db, `INSERT INTO services (id, name, ip_port, description) VALUES
			(1,'web','10.0.0.5:8080','Web'),(2,'db','192.168.1.10:5432','Database')`)
	case "v1.1":
		mustExec(t, db, `INSERT INTO services (id, name, ip_port, hostname, description) VALUES
			(1,'web','10.0.0.5:8080','static-placeholder-hostname','Web'),
			(2,'db','192.168.1.10:5432','db.internal:5432','Database')`)
	default:
		mustExec(t, db, `INSERT INTO services (id, name, hostname, ip, port, description) VALUES
			(1,'web','static-placeholder-hostname',?,8080,'Web'),
			(2,'db','db.internal:5432',?,5432,'Database')`, web, dbIP)
	}

	mustExec(t, db, `INSERT INTO role_services (role_id, service_id) VALUES (3,1)`)
	mustExec(t, db, `INSERT INTO user_extra_services (user_id, service_id) VALUES (2,2)`)
	mustExec(t, db, `INSERT INTO user_active_services (user_id, service_id, updated_at, time_left) VALUES (2,1,'2026-09-09 10:03:40.123456789+05:30',30)`)
	if version == "v1.2" {
		mustExec(t, db, `INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ('tok', 2, '2026-09-09 10:03:40.123456789+05:30')`)
	}
	_ = db.Close()
}

func freshDBPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aegis.db")
	if err := Migrate(context.Background(), path); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return path
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	migs, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) != latestVersion {
		t.Fatalf("expected %d embedded migrations, found %d (update latestVersion in this test)", latestVersion, len(migs))
	}
	for _, m := range migs {
		if strings.TrimSpace(m.Down) == "" {
			t.Errorf("migration %04d_%s has no down file", m.Version, m.Name)
		}
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	ok := fstest.MapFS{
		"0001_a.up.sql":   {Data: []byte("SELECT 1;")},
		"0001_a.down.sql": {Data: []byte("SELECT 1;")},
		"0002_b.up.sql":   {Data: []byte("SELECT 1;")},
	}
	migs, err := loadMigrations(ok)
	if err != nil || len(migs) != 2 || migs[1].Down != "" {
		t.Fatalf("valid set rejected or misread: %v %+v", err, migs)
	}

	bad := map[string]fstest.MapFS{
		"gap":           {"0001_a.up.sql": {Data: []byte("x")}, "0003_c.up.sql": {Data: []byte("x")}},
		"starts at 2":   {"0002_a.up.sql": {Data: []byte("x")}},
		"bad name":      {"1_a.sql": {Data: []byte("x")}},
		"missing up":    {"0001_a.down.sql": {Data: []byte("x")}},
		"mismatch name": {"0001_a.up.sql": {Data: []byte("x")}, "0001_b.down.sql": {Data: []byte("x")}},
	}
	for name, fsys := range bad {
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMigrateFreshDatabase(t *testing.T) {
	dbPath := freshDBPath(t)
	db := openRaw(t, dbPath)

	if v := schemaVersion(t, db); v != latestVersion {
		t.Errorf("expected schema version %d, got %d", latestVersion, v)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM schema_migrations`); n != 1 {
		t.Errorf("schema_migrations must hold a single row, has %d", n)
	}
	if got := mustString(t, db, `SELECT group_concat(name, ',') FROM (SELECT name FROM roles ORDER BY id)`); got != "root,admin,user" {
		t.Errorf("unexpected seeded roles: %s", got)
	}
	if n := len(backupFiles(t, dbPath)); n != 0 {
		t.Errorf("a brand new database must not be backed up, found %d backups", n)
	}

	// Constraints the application relies on.
	mustExec(t, db, `INSERT INTO services (name, hostname, ip, port) VALUES ('svc', '10.0.0.1:80', 167772161, 80)`)
	_, err := db.Exec(`INSERT INTO services (name, hostname, ip, port) VALUES ('svc', '10.0.0.2:80', 167772162, 80)`)
	if !errors.Is(translateWriteError(err), ErrDuplicate) {
		t.Errorf("duplicate service name must be rejected, got %v", err)
	}
	if _, err := db.Exec(`INSERT INTO services (name, hostname, ip, port) VALUES ('big', 'h:1', 1, 70000)`); err == nil {
		t.Error("out-of-range port must be rejected")
	}
	if _, err := db.Exec(`INSERT INTO users (username, password, role_id) VALUES ('norole', 'x', NULL)`); err == nil {
		t.Error("user without a role must be rejected")
	}
	if _, err := db.Exec(`INSERT INTO users (username, password, role_id) VALUES ('nopass', NULL, 3)`); err == nil {
		t.Error("local user without a password must be rejected")
	}
	mustExec(t, db, `INSERT INTO users (username, password, role_id, provider, provider_id) VALUES ('sso1', NULL, 3, 'github', '42')`)
	_, err = db.Exec(`INSERT INTO users (username, password, role_id, provider, provider_id) VALUES ('sso2', NULL, 3, 'github', '42')`)
	if !errors.Is(translateWriteError(err), ErrDuplicate) {
		t.Errorf("one account per external identity expected, got %v", err)
	}
	if _, err := db.Exec(`DELETE FROM roles WHERE id = 3`); err == nil {
		t.Error("deleting a role that still has users must be rejected")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dbPath := freshDBPath(t)
	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	db := openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != latestVersion {
		t.Errorf("expected version %d, got %d", latestVersion, v)
	}
	if n := len(backupFiles(t, dbPath)); n != 0 {
		t.Errorf("no backup expected when nothing is pending, found %d", n)
	}
}

func TestMigrateUpgradesEveryReleasedVersion(t *testing.T) {
	freshSig := schemaSignature(t, openRaw(t, freshDBPath(t)))

	for _, version := range []string{"v1.0", "v1.1", "v1.1.1", "v1.2"} {
		t.Run(version, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "aegis.db")
			buildLegacyDB(t, dbPath, version)

			st, err := MigrationStatus(context.Background(), dbPath)
			if err != nil {
				t.Fatalf("MigrationStatus: %v", err)
			}
			if !st.Unversioned || st.Current == 0 || len(st.Pending) == 0 {
				t.Errorf("legacy database should be detected as unversioned with pending migrations: %+v", st)
			}

			if err := Migrate(context.Background(), dbPath); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			db := openRaw(t, dbPath)

			if v := schemaVersion(t, db); v != latestVersion {
				t.Errorf("expected version %d, got %d", latestVersion, v)
			}
			if n := len(backupFiles(t, dbPath)); n != 1 {
				t.Fatalf("expected one pre-migration backup, found %d", n)
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM pragma_foreign_key_check`); n != 0 {
				t.Errorf("foreign key violations after migration: %d", n)
			}

			// Data survives (rebuilding tables must not cascade-delete children).
			wantRows := map[string]int{"users": 2, "services": 2, "role_services": 1, "user_extra_services": 1, "user_active_services": 1}
			if version == "v1.2" {
				wantRows["refresh_tokens"] = 1
			}
			for table, want := range wantRows {
				if got := mustCount(t, db, `SELECT COUNT(*) FROM `+table); got != want {
					t.Errorf("%s: expected %d rows, got %d", table, want, got)
				}
			}

			// The service endpoint is converted correctly.
			if got := mustCount(t, db, `SELECT ip FROM services WHERE id = 1`); got != ipInt(10, 0, 0, 5) {
				t.Errorf("web ip = %d", got)
			}
			if got := mustCount(t, db, `SELECT port FROM services WHERE id = 1`); got != 8080 {
				t.Errorf("web port = %d", got)
			}
			if got := mustCount(t, db, `SELECT ip FROM services WHERE id = 2`); got != ipInt(192, 168, 1, 10) {
				t.Errorf("db ip = %d", got)
			}
			if got := mustCount(t, db, `SELECT port FROM services WHERE id = 2`); got != 5432 {
				t.Errorf("db port = %d", got)
			}
			// The placeholder hostname is replaced in every upgrade path.
			if got := mustString(t, db, `SELECT hostname FROM services WHERE id = 1`); got != "10.0.0.5:8080" {
				t.Errorf("web hostname = %q", got)
			}
			wantDBHost := "db.internal:5432"
			if version == "v1.0" {
				wantDBHost = "192.168.1.10:5432" // v1.0 only had ip_port
			}
			if got := mustString(t, db, `SELECT hostname FROM services WHERE id = 2`); got != wantDBHost {
				t.Errorf("db hostname = %q, want %q", got, wantDBHost)
			}

			if got := mustString(t, db, `SELECT provider FROM users WHERE id = 2`); got != "local" {
				t.Errorf("provider = %q", got)
			}
			if got := mustString(t, db, `SELECT CAST(updated_at AS TEXT) FROM user_active_services`); got != "2026-09-09 04:33:40.123" {
				t.Errorf("updated_at must be UTC, got %q", got)
			}

			if sig := schemaSignature(t, db); sig != freshSig {
				t.Errorf("upgraded schema differs from a fresh install:\n--- upgraded\n%s\n--- fresh\n%s", sig, freshSig)
			}
		})
	}
}

func TestMigrateKeepsMalformedLegacyServices(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	buildLegacyDB(t, dbPath, "v1.1")
	db := openRawFK(t, dbPath, "off")
	mustExec(t, db, `INSERT INTO services (id, name, ip_port, hostname, description) VALUES
		(10,'no-port','10.0.0.1','static-placeholder-hostname',''),
		(11,'hostname','db.local:5432','static-placeholder-hostname',''),
		(12,'big-octet','300.1.1.1:80','static-placeholder-hostname',''),
		(13,'big-port','10.0.0.1:99999','static-placeholder-hostname',''),
		(14,'three-octets','1.2.3:80','static-placeholder-hostname',''),
		(15,'empty-octet','1..3.4:80','static-placeholder-hostname',''),
		(16,'max','255.255.255.255:65535','static-placeholder-hostname',''),
		(17,'zero','0.0.0.0:0','static-placeholder-hostname','')`)
	_ = db.Close()

	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	db = openRaw(t, dbPath)

	if n := mustCount(t, db, `SELECT COUNT(*) FROM services`); n != 10 {
		t.Fatalf("no service may be dropped: expected 10 rows, got %d", n)
	}
	type want struct {
		ip, port int
		host     string
	}
	cases := map[string]want{
		"no-port":      {ipInt(10, 0, 0, 1), 0, "10.0.0.1"},
		"hostname":     {0, 5432, "db.local:5432"},
		"big-octet":    {0, 80, "300.1.1.1:80"},
		"big-port":     {ipInt(10, 0, 0, 1), 0, "10.0.0.1:99999"},
		"three-octets": {0, 80, "1.2.3:80"},
		"empty-octet":  {0, 80, "1..3.4:80"},
		"max":          {4294967295, 65535, "255.255.255.255:65535"},
		"zero":         {0, 0, "0.0.0.0:0"},
	}
	for name, w := range cases {
		var ip, port int
		var host string
		if err := db.QueryRow(`SELECT ip, port, hostname FROM services WHERE name = ?`, name).Scan(&ip, &port, &host); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ip != w.ip || port != w.port || host != w.host {
			t.Errorf("%s: got ip=%d port=%d hostname=%q, want ip=%d port=%d hostname=%q", name, ip, port, host, w.ip, w.port, w.host)
		}
	}
}

func TestMigrateCleansUpProblemData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	buildLegacyDB(t, dbPath, "v1.2")
	db := openRawFK(t, dbPath, "off")
	mustExec(t, db, `INSERT INTO users (id, username, password, role_id, is_active, provider) VALUES
		(3,'norole','hash',NULL,1,'local'),
		(4,'badrole','hash',99,NULL,NULL)`)
	mustExec(t, db, `INSERT INTO users (id, username, password, role_id, provider, provider_id, email) VALUES
		(5,'sso@example.com',NULL,3,'github','77','sso@example.com')`)
	mustExec(t, db, `INSERT INTO services (id, name, hostname, ip, port) VALUES (3,'web','10.0.0.9:80',?,80)`, ipInt(10, 0, 0, 9))
	// orphans left behind by versions that did not enforce foreign keys
	mustExec(t, db, `INSERT INTO role_services (role_id, service_id) VALUES (3, 777)`)
	mustExec(t, db, `INSERT INTO user_extra_services (user_id, service_id) VALUES (888, 1)`)
	mustExec(t, db, `INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ('orphan', 999, '2030-01-01 00:00:00')`)
	_ = db.Close()

	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	db = openRaw(t, dbPath)

	if got := mustString(t, db, `SELECT name FROM services WHERE id = 3`); got != "web (3)" {
		t.Errorf("duplicate service name must be suffixed, got %q", got)
	}
	if got := mustString(t, db, `SELECT name FROM services WHERE id = 1`); got != "web" {
		t.Errorf("the oldest service keeps its name, got %q", got)
	}
	for id, wantRole := range map[int]string{3: "user", 4: "user", 1: "root"} {
		if got := mustString(t, db, `SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?`, id); got != wantRole {
			t.Errorf("user %d role = %q, want %q", id, got, wantRole)
		}
	}
	if got := mustString(t, db, `SELECT is_active || '/' || provider FROM users WHERE id = 4`); got != "1/local" {
		t.Errorf("NULL flags must get defaults, got %q", got)
	}
	if got := mustString(t, db, `SELECT provider_id FROM users WHERE id = 5`); got != "77" {
		t.Errorf("SSO user lost data, provider_id=%q", got)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM role_services WHERE service_id = 777`) +
		mustCount(t, db, `SELECT COUNT(*) FROM user_extra_services WHERE user_id = 888`) +
		mustCount(t, db, `SELECT COUNT(*) FROM refresh_tokens WHERE token = 'orphan'`); n != 0 {
		t.Errorf("orphan rows must be removed, %d left", n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM pragma_foreign_key_check`); n != 0 {
		t.Errorf("foreign key violations after migration: %d", n)
	}
	if got := mustString(t, db, `SELECT CAST(expires_at AS TEXT) FROM refresh_tokens WHERE token = 'tok'`); got != "2026-09-09 04:33:40.123" {
		t.Errorf("expires_at must be converted to UTC, got %q", got)
	}
	// cascades still work after the rebuilds
	mustExec(t, db, `DELETE FROM services WHERE id = 1`)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM role_services WHERE service_id = 1`); n != 0 {
		t.Error("ON DELETE CASCADE must still work after the rebuild")
	}
}

func TestMigrateRejectsUnrecognizedSchemas(t *testing.T) {
	cases := map[string]string{
		"unrelated database": `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);`,
		"missing tables":     `CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT);`,
		"leftover table": fxRoles + fxUsersV10 + fxServicesV111 +
			`CREATE TABLE services_new (id INTEGER PRIMARY KEY);`,
		"mixed up columns": fxRoles + fxUsersV12 +
			`CREATE TABLE services (id INTEGER PRIMARY KEY, name TEXT);`,
	}
	for name, ddl := range cases {
		t.Run(name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "aegis.db")
			db := openRawFK(t, dbPath, "off")
			mustExec(t, db, ddl)
			_ = db.Close()

			err := Migrate(context.Background(), dbPath)
			if !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("expected ErrUnknownSchema, got %v", err)
			}
			// nothing may have been touched
			db = openRaw(t, dbPath)
			if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_migrations'`); n != 0 {
				t.Error("a rejected database must not get a version table")
			}
			if n := len(backupFiles(t, dbPath)); n != 0 {
				t.Errorf("a rejected database must not be backed up, found %d", n)
			}
		})
	}
}

func TestMigrateRejectsNewerSchema(t *testing.T) {
	dbPath := freshDBPath(t)
	db := openRaw(t, dbPath)
	mustExec(t, db, `DELETE FROM schema_migrations`)
	mustExec(t, db, `INSERT INTO schema_migrations (version, dirty) VALUES (999, 0)`)

	if err := Migrate(context.Background(), dbPath); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew, got %v", err)
	}
}

func TestMigrateRejectsDirtyDatabase(t *testing.T) {
	dbPath := freshDBPath(t)
	db := openRaw(t, dbPath)
	mustExec(t, db, `UPDATE schema_migrations SET dirty = 1`)

	if err := Migrate(context.Background(), dbPath); !errors.Is(err, ErrDirtyMigration) {
		t.Fatalf("expected ErrDirtyMigration, got %v", err)
	}
}

func TestFailedMigrationIsRolledBack(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	db, err := openMigrationDB(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	migs := []Migration{
		{Version: 1, Name: "ok", Up: `CREATE TABLE t1 (id INTEGER);`},
		{Version: 2, Name: "broken", Up: `CREATE TABLE t2 (id INTEGER); INSERT INTO does_not_exist VALUES (1);`},
		{Version: 3, Name: "never", Up: `CREATE TABLE t3 (id INTEGER);`},
	}
	err = migrateUp(context.Background(), db, dbPath, migs)
	if err == nil || !strings.Contains(err.Error(), "0002_broken") {
		t.Fatalf("expected a failure naming migration 0002_broken, got %v", err)
	}

	if v := schemaVersion(t, db); v != 1 {
		t.Errorf("version must stay at the last successful migration (1), got %d", v)
	}
	for table, want := range map[string]int{"t1": 1, "t2": 0, "t3": 0} {
		if got := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, table); got != want {
			t.Errorf("table %s: exists=%d, want %d (partial changes must be rolled back)", table, got, want)
		}
	}
}

func TestMigrateDownAndUpAgain(t *testing.T) {
	dbPath := freshDBPath(t)
	db := openRaw(t, dbPath)
	mustExec(t, db, `INSERT INTO services (name, hostname, ip, port) VALUES ('web', '10.0.0.5:8080', ?, 8080)`, ipInt(10, 0, 0, 5))
	mustExec(t, db, `INSERT INTO users (username, password, role_id) VALUES ('alice', 'x', 3)`)
	mustExec(t, db, `INSERT INTO user_extra_services (user_id, service_id) VALUES (1, 1)`)
	_ = db.Close()

	// back to the first version: v1.0 schema with the data converted back
	if err := MigrateDown(context.Background(), dbPath, latestVersion-1); err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}
	db = openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != 1 {
		t.Fatalf("expected version 1 after rolling back, got %d", v)
	}
	if got := mustString(t, db, `SELECT ip_port FROM services WHERE name = 'web'`); got != "10.0.0.5:8080" {
		t.Errorf("rolled-back ip_port = %q", got)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM user_extra_services`); n != 1 {
		t.Errorf("link rows lost while rolling back: %d", n)
	}
	_ = db.Close()

	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("Migrate after rollback: %v", err)
	}
	db = openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != latestVersion {
		t.Errorf("expected version %d after re-applying, got %d", latestVersion, v)
	}
	if got := mustCount(t, db, `SELECT ip FROM services WHERE name = 'web'`); got != ipInt(10, 0, 0, 5) {
		t.Errorf("re-applied ip = %d", got)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM user_extra_services`); n != 1 {
		t.Errorf("link rows lost while re-applying: %d", n)
	}
}

func TestMigrateDownToEmptyAndBack(t *testing.T) {
	dbPath := freshDBPath(t)
	freshSig := schemaSignature(t, openRaw(t, dbPath))

	if err := MigrateDown(context.Background(), dbPath, latestVersion); err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}
	db := openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != 0 {
		t.Errorf("expected version 0, got %d", v)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT IN ('schema_migrations', 'sqlite_sequence')`); n != 0 {
		t.Errorf("expected no application tables after rolling everything back, found %d", n)
	}
	_ = db.Close()

	if err := Migrate(context.Background(), dbPath); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if sig := schemaSignature(t, openRaw(t, dbPath)); sig != freshSig {
		t.Error("schema after rolling back to empty and migrating again differs from a fresh install")
	}
}

func TestMigrateConcurrentStarts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")

	const runners = 4
	errs := make([]error, runners)
	var wg sync.WaitGroup
	for i := 0; i < runners; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Migrate(context.Background(), dbPath)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}
	db := openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != latestVersion {
		t.Errorf("expected version %d, got %d", latestVersion, v)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM roles`); n != 3 {
		t.Errorf("seed data must be inserted exactly once, found %d roles", n)
	}
}

func TestMigrateConcurrentStartsOnLegacyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	buildLegacyDB(t, dbPath, "v1.1")

	const runners = 4
	errs := make([]error, runners)
	var wg sync.WaitGroup
	for i := 0; i < runners; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Migrate(context.Background(), dbPath)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}
	db := openRaw(t, dbPath)
	if v := schemaVersion(t, db); v != latestVersion {
		t.Errorf("expected version %d, got %d", latestVersion, v)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM services`); n != 2 {
		t.Errorf("expected 2 services, got %d", n)
	}
	if got := mustCount(t, db, `SELECT ip FROM services WHERE id = 1`); got != ipInt(10, 0, 0, 5) {
		t.Errorf("web ip = %d (migrations must not run twice)", got)
	}
	if len(backupFiles(t, dbPath)) < 1 {
		t.Error("expected at least one pre-migration backup")
	}
}

func TestMigrationStatus(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", "aegis.db")
	st, err := MigrationStatus(context.Background(), missing)
	if err != nil {
		t.Fatalf("MigrationStatus on a missing file: %v", err)
	}
	if st.Current != 0 || len(st.Pending) != latestVersion {
		t.Errorf("a missing database has everything pending: %+v", st)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("MigrationStatus must not create the database file")
	}

	st, err = MigrationStatus(context.Background(), freshDBPath(t))
	if err != nil {
		t.Fatalf("MigrationStatus: %v", err)
	}
	if st.Current != latestVersion || st.Latest != latestVersion || len(st.Pending) != 0 || st.Unversioned {
		t.Errorf("an up-to-date database: %+v", st)
	}
}

func TestInitDBCreatesDirectoryAndEnforcesForeignKeysOnEveryConnection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	db, err := InitDB(dir, 4, 4, 0)
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := os.Stat(filepath.Join(dir, DBFileName)); err != nil {
		t.Fatalf("database file not created: %v", err)
	}

	ctx := context.Background()
	var conns []*sql.Conn
	for i := 0; i < 4; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns = append(conns, c)
		var fk int
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("pragma: %v", err)
		}
		if fk != 1 {
			t.Errorf("connection %d does not enforce foreign keys", i)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
