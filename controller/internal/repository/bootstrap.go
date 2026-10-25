package repository

import (
	"Aegis/controller/internal/utils"
	"database/sql"
	"errors"
	"fmt"
)

// EnsureRootUser creates the initial 'root' account when the database has no
// user holding the root role.
func EnsureRootUser(db *sql.DB, password string) (generated string, created bool, err error) {
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.name = 'root'`).Scan(&count)
	if err != nil {
		return "", false, fmt.Errorf("check for root user: %w", err)
	}
	if count > 0 {
		return "", false, nil
	}

	if password == "" {
		generated, err = utils.GenerateSecureToken(18)
		if err != nil {
			return "", false, fmt.Errorf("generate root password: %w", err)
		}
		password = generated
	}
	hash, err := utils.HashPassword(password)
	if err != nil {
		return "", false, fmt.Errorf("hash root password: %w", err)
	}

	_, err = db.Exec(`INSERT INTO users (username, password, role_id, is_active)
		SELECT 'root', ?, id, 1 FROM roles WHERE name = 'root'`, hash)
	if err != nil {
		if errors.Is(translateWriteError(err), ErrDuplicate) {
			return "", false, fmt.Errorf("a user named 'root' exists but does not have the root role; fix it manually: %w", err)
		}
		return "", false, fmt.Errorf("create root user: %w", err)
	}
	return generated, true, nil
}
