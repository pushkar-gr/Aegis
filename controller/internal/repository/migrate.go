package repository

import (
	"Aegis/controller/migrations"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

// versionTable records the applied schema version.
const versionTable = "schema_migrations"

// Migrations 0001-0004 is for already released versions.
const (
	legacyV10  = 1 // v1.0
	legacyV11  = 2 // v1.1
	legacyV111 = 3 // v1.1.1
	legacyV12  = 4 // v1.2
)

var (
	// ErrUnknownSchema is when database tables do not match any released version.
	ErrUnknownSchema = errors.New("unrecognized database schema")

	// ErrSchemaTooNew is when database was migrated by a newer version application.
	ErrSchemaTooNew = errors.New("database schema is newer than this application supports")

	// ErrDirtyMigration is when version table is marked dirty.
	ErrDirtyMigration = errors.New("database is marked dirty by a failed migration")
)

// Migration is one numbered schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

var migrationFileRE = regexp.MustCompile(`^(\d+)_([A-Za-z0-9_]+)\.(up|down)\.sql$`)

// loadMigrations reads NNNN_name.up.sql / NNNN_name.down.sql files from fsys.
func loadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	byVersion := map[int]*Migration{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q must be named NNNN_name.up.sql or NNNN_name.down.sql", e.Name())
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("migration file %q has an invalid version", e.Name())
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}

		mig := byVersion[version]
		if mig == nil {
			mig = &Migration{Version: version, Name: m[2]}
			byVersion[version] = mig
		} else if mig.Name != m[2] {
			return nil, fmt.Errorf("migration %04d has two different names: %q and %q", version, mig.Name, m[2])
		}
		if m[3] == "up" {
			mig.Up = string(body)
		} else {
			mig.Down = string(body)
		}
	}

	list := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		list = append(list, *m)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Version < list[j].Version })

	for i, m := range list {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous starting at 1: expected %04d, found %04d", i+1, m.Version)
		}
		if strings.TrimSpace(m.Up) == "" {
			return nil, fmt.Errorf("migration %04d_%s has no up file", m.Version, m.Name)
		}
	}
	return list, nil
}

// Status describes the state of a database relative to the embedded migrations.
type Status struct {
	Current     int      // applied version (0 = empty database)
	Latest      int      // latest embedded version
	Pending     []string // names of migrations that should be applied
	Unversioned bool     // fi Current was detected from the schema of a pre-migration database
}

// Migrate brings the database up to the latest schema version. File is created if does not exist.
func Migrate(ctx context.Context, dbPath string) error {
	migs, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	db, err := openMigrationDB(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return migrateUp(ctx, db, dbPath, migs)
}

// MigrateDown reverts the last `steps` applied migrations (newest first).
func MigrateDown(ctx context.Context, dbPath string, steps int) error {
	if steps < 1 {
		return fmt.Errorf("steps must be at least 1")
	}
	migs, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	db, err := openMigrationDB(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return migrateDown(ctx, db, dbPath, migs, steps)
}

// MigrationStatus gets the schema version of the database without changing it.
func MigrationStatus(ctx context.Context, dbPath string) (*Status, error) {
	migs, err := loadMigrations(migrations.FS)
	if err != nil {
		return nil, err
	}
	st := &Status{Latest: migs[len(migs)-1].Version}

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		for _, m := range migs {
			st.Pending = append(st.Pending, fmt.Sprintf("%04d_%s", m.Version, m.Name))
		}
		return st, nil
	}

	db, err := openMigrationDB(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	cur, unversioned, err := currentVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	st.Current, st.Unversioned = cur, unversioned
	for _, m := range migs {
		if m.Version > cur {
			st.Pending = append(st.Pending, fmt.Sprintf("%04d_%s", m.Version, m.Name))
		}
	}
	return st, nil
}

func openMigrationDB(dbPath string) (*sql.DB, error) {
	dsn, err := sqliteDSN(dbPath, map[string]string{
		"_foreign_keys": "off",
		"_busy_timeout": "5000",
		"_journal_mode": "WAL",
		"_txlock":       "immediate",
	})
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)

	var fk int
	err = retryBusy(context.Background(), func() error {
		return db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read foreign_keys pragma: %w", err)
	}
	if fk != 0 {
		_ = db.Close()
		return nil, fmt.Errorf("foreign key enforcement must be off while migrating")
	}
	return db, nil
}

func migrateUp(ctx context.Context, db *sql.DB, dbPath string, migs []Migration) error {
	latest := migs[len(migs)-1].Version

	cur, unversioned, err := currentVersion(ctx, db)
	if err != nil {
		return err
	}
	if cur > latest {
		return fmt.Errorf("%w: database is at version %d, this binary knows up to %d", ErrSchemaTooNew, cur, latest)
	}

	if cur < latest {
		if backupPath, err := backupBeforeMigrate(ctx, db, dbPath, cur); err != nil {
			return fmt.Errorf("back up database before migrating: %w", err)
		} else if backupPath != "" {
			log.Printf("[INFO] [database] backed up existing database to %s", backupPath)
		}
	}

	if unversioned {
		log.Printf("[INFO] [database] existing database without version information recognized as schema version %d", cur)
		if err := stampVersion(ctx, db, cur); err != nil {
			return err
		}
	}

	for {
		applied, err := applyNext(ctx, db, migs)
		if err != nil {
			return err
		}
		if !applied {
			break
		}
	}

	return checkForeignKeys(ctx, db)
}

// applyNext applies the first pending migration inside one transaction.
func applyNext(ctx context.Context, db *sql.DB, migs []Migration) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := ensureVersionTable(ctx, tx); err != nil {
		return false, err
	}
	cur, dirty, err := readVersion(ctx, tx)
	if err != nil {
		return false, err
	}
	if dirty {
		return false, ErrDirtyMigration
	}

	var next *Migration
	for i := range migs {
		if migs[i].Version > cur {
			next = &migs[i]
			break
		}
	}
	if next == nil {
		return false, nil
	}

	started := time.Now()
	if _, err := tx.ExecContext(ctx, next.Up); err != nil {
		return false, fmt.Errorf("migration %04d_%s failed: %w", next.Version, next.Name, err)
	}
	if err := writeVersion(ctx, tx, next.Version); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit migration %04d_%s: %w", next.Version, next.Name, err)
	}
	log.Printf("[INFO] [database] applied migration %04d_%s (%s)", next.Version, next.Name, time.Since(started).Round(time.Millisecond))
	return true, nil
}

func migrateDown(ctx context.Context, db *sql.DB, dbPath string, migs []Migration, steps int) error {
	cur, unversioned, err := currentVersion(ctx, db)
	if err != nil {
		return err
	}
	if unversioned {
		return fmt.Errorf("database has no version information; run the migrations up first")
	}
	if cur == 0 {
		return nil
	}

	if backupPath, err := backupBeforeMigrate(ctx, db, dbPath, cur); err != nil {
		return fmt.Errorf("back up database before rolling back: %w", err)
	} else if backupPath != "" {
		log.Printf("[INFO] [database] backed up existing database to %s", backupPath)
	}

	for i := 0; i < steps; i++ {
		reverted, err := revertLatest(ctx, db, migs)
		if err != nil {
			return err
		}
		if !reverted {
			break
		}
	}
	return checkForeignKeys(ctx, db)
}

func revertLatest(ctx context.Context, db *sql.DB, migs []Migration) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin rollback: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := ensureVersionTable(ctx, tx); err != nil {
		return false, err
	}
	cur, dirty, err := readVersion(ctx, tx)
	if err != nil {
		return false, err
	}
	if dirty {
		return false, ErrDirtyMigration
	}
	if cur == 0 {
		return false, nil
	}
	if cur > len(migs) {
		return false, fmt.Errorf("%w: database is at version %d, this binary knows up to %d", ErrSchemaTooNew, cur, len(migs))
	}

	m := migs[cur-1]
	if strings.TrimSpace(m.Down) == "" {
		return false, fmt.Errorf("migration %04d_%s has no down migration", m.Version, m.Name)
	}
	if _, err := tx.ExecContext(ctx, m.Down); err != nil {
		return false, fmt.Errorf("rolling back %04d_%s failed: %w", m.Version, m.Name, err)
	}
	if err := writeVersion(ctx, tx, m.Version-1); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit rollback %04d_%s: %w", m.Version, m.Name, err)
	}
	log.Printf("[INFO] [database] rolled back migration %04d_%s", m.Version, m.Name)
	return true, nil
}

// queryer is satisfied by *sql.DB and *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func ensureVersionTable(ctx context.Context, q queryer) error {
	if _, err := q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+versionTable+` (version uint64, dirty bool)`); err != nil {
		return fmt.Errorf("create %s table: %w", versionTable, err)
	}
	if _, err := q.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON `+versionTable+` (version)`); err != nil {
		return fmt.Errorf("create %s index: %w", versionTable, err)
	}
	return nil
}

// readVersion returns the recorded version. 0 when nothing is recorded.
func readVersion(ctx context.Context, q queryer) (version int, dirty bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT version, dirty FROM `+versionTable+` LIMIT 1`).Scan(&version, &dirty)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read schema version: %w", err)
	}
	return version, dirty, nil
}

func writeVersion(ctx context.Context, q queryer, version int) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM `+versionTable); err != nil {
		return fmt.Errorf("write schema version: %w", err)
	}
	if version > 0 {
		if _, err := q.ExecContext(ctx, `INSERT INTO `+versionTable+` (version, dirty) VALUES (?, 0)`, version); err != nil {
			return fmt.Errorf("write schema version: %w", err)
		}
	}
	return nil
}

// stampVersion records the detected version of an unversioned database.
func stampVersion(ctx context.Context, db *sql.DB, version int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin stamp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := ensureVersionTable(ctx, tx); err != nil {
		return err
	}
	current, _, err := readVersion(ctx, tx)
	if err != nil {
		return err
	}
	if current == 0 {
		if err := writeVersion(ctx, tx, version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// currentVersion returns the schema version of the database.
func currentVersion(ctx context.Context, db *sql.DB) (version int, unversioned bool, err error) {
	hasTable, err := tableExists(ctx, db, versionTable)
	if err != nil {
		return 0, false, err
	}
	if hasTable {
		v, dirty, err := readVersion(ctx, db)
		if err != nil {
			return 0, false, err
		}
		if dirty {
			return 0, false, ErrDirtyMigration
		}
		if v > 0 {
			return v, false, nil
		}
	}

	detected, err := detectLegacyVersion(ctx, db)
	if err != nil {
		return 0, false, err
	}
	return detected, detected > 0, nil
}

func tableExists(ctx context.Context, q queryer, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}

func listTables(ctx context.Context, q queryer) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	tables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables[name] = true
	}
	return tables, rows.Err()
}

func listColumns(ctx context.Context, q queryer, table string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notNull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[strings.ToLower(name)] = true
	}
	return cols, rows.Err()
}

// detectLegacyVersion gets the schema of a database that has no version. Returns 0 for an empty database.
func detectLegacyVersion(ctx context.Context, db *sql.DB) (int, error) {
	tables, err := listTables(ctx, db)
	if err != nil {
		return 0, err
	}
	delete(tables, versionTable)
	if len(tables) == 0 {
		return 0, nil
	}

	for _, leftover := range []string{"services_new", "users_new", "services_old", "users_old"} {
		if tables[leftover] {
			return 0, fmt.Errorf("%w: leftover table %q from an interrupted manual migration; inspect and drop it first", ErrUnknownSchema, leftover)
		}
	}
	for _, core := range []string{"roles", "users", "services"} {
		if !tables[core] {
			return 0, fmt.Errorf("%w: table %q is missing", ErrUnknownSchema, core)
		}
	}

	svc, err := listColumns(ctx, db, "services")
	if err != nil {
		return 0, err
	}
	usr, err := listColumns(ctx, db, "users")
	if err != nil {
		return 0, err
	}

	switch {
	case svc["ip_port"] && !svc["hostname"]:
		return legacyV10, nil
	case svc["ip_port"] && svc["hostname"]:
		return legacyV11, nil
	case svc["ip"] && svc["port"] && svc["hostname"] && !usr["provider"]:
		return legacyV111, nil
	case svc["ip"] && svc["port"] && svc["hostname"] && usr["provider"] && tables["refresh_tokens"]:
		return legacyV12, nil
	}
	return 0, fmt.Errorf("%w: the services and users tables do not match any released version", ErrUnknownSchema)
}

func backupBeforeMigrate(ctx context.Context, db *sql.DB, dbPath string, current int) (string, error) {
	hasUsers, err := tableExists(ctx, db, "users")
	if err != nil || !hasUsers {
		return "", err
	}
	// Nanosecond timestamp and pid keep names unique when several instances
	// start at the same moment.
	backupPath := fmt.Sprintf("%s.pre-migration-v%d-%s-%d.bak", dbPath, current, time.Now().UTC().Format("20060102T150405.000000000Z"), os.Getpid())
	if _, err := os.Stat(backupPath); err == nil {
		return "", fmt.Errorf("backup file %s already exists", backupPath)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

// checkForeignKeys fails if any row violates a foreign key constraint.
func checkForeignKeys(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("foreign key check: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var violations []string
	for rows.Next() {
		var table, parent string
		var rowid, fkid sql.NullInt64
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return fmt.Errorf("foreign key check: %w", err)
		}
		violations = append(violations, fmt.Sprintf("%s(rowid=%d)->%s", table, rowid.Int64, parent))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("foreign key check: %w", err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("foreign key violations after migration: %s", strings.Join(violations, ", "))
	}
	return nil
}

func isBusy(err error) bool {
	var se sqlite3.Error
	if errors.As(err, &se) && (se.Code == sqlite3.ErrBusy || se.Code == sqlite3.ErrLocked) {
		return true
	}
	return strings.Contains(err.Error(), "database is locked")
}

func retryBusy(ctx context.Context, fn func() error) error {
	deadline := time.Now().Add(15 * time.Second)
	delay := 10 * time.Millisecond
	for {
		err := fn()
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 250*time.Millisecond {
			delay *= 2
		}
	}
}
