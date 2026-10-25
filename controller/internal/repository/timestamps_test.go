package repository

import (
	"errors"
	"testing"
	"time"
)

func TestRefreshTokenExpiryIsTimezoneIndependent(t *testing.T) {
	zones := map[string]*time.Location{
		"UTC":        time.UTC,
		"IST(+5:30)": time.FixedZone("IST", 5*3600+1800),
		"EST(-5:00)": time.FixedZone("EST", -5*3600),
	}

	for name, zone := range zones {
		t.Run(name, func(t *testing.T) {
			orig := time.Local
			time.Local = zone
			t.Cleanup(func() { time.Local = orig })

			db := newMigratedDB(t)
			mustExec(t, db, `INSERT INTO users (id, username, password, role_id) VALUES (1, 'tokuser', 'x', 3)`)
			repo, err := NewUserRepository(db)
			if err != nil {
				t.Fatalf("NewUserRepository: %v", err)
			}

			now := time.Now()
			if err := repo.CreateRefreshToken("expired", 1, now.Add(-time.Hour)); err != nil {
				t.Fatalf("create expired: %v", err)
			}
			if err := repo.CreateRefreshToken("valid", 1, now.Add(time.Hour)); err != nil {
				t.Fatalf("create valid: %v", err)
			}

			if _, err := repo.GetRefreshToken("expired"); !errors.Is(err, ErrNotFound) {
				t.Errorf("expired token must not be accepted, got %v", err)
			}
			if _, err := repo.GetRefreshToken("valid"); err != nil {
				t.Errorf("valid token must be accepted, got %v", err)
			}

			if err := repo.CleanupExpiredRefreshTokens(); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM refresh_tokens WHERE token = 'expired'`); n != 0 {
				t.Error("cleanup must delete the expired token")
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM refresh_tokens WHERE token = 'valid'`); n != 1 {
				t.Error("cleanup must keep the token that is still valid")
			}
		})
	}
}
