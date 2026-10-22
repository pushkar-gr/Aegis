package repository

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/mattn/go-sqlite3"
)

var (
	// ErrNotFound is returned when a lookup matches no row. It is the same
	// value as sql.ErrNoRows, so callers never need to import database/sql
	// just to detect a missing record.
	ErrNotFound = sql.ErrNoRows

	// ErrDuplicate is returned when a write violates a UNIQUE or PRIMARY KEY
	// constraint. The original driver error stays in the chain.
	ErrDuplicate = errors.New("duplicate record")
)

// translateWriteError converts driver-specific constraint failures into
// repository errors so upper layers never inspect error text.
func translateWriteError(err error) error {
	if err == nil {
		return nil
	}
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) &&
		(sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique ||
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
		return fmt.Errorf("%w: %w", ErrDuplicate, err)
	}
	return err
}
