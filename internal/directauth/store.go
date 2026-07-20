package directauth

import (
	"context"
	"database/sql"
)

// Store persists a per-user encrypted Google refresh token. Interface so handlers
// are unit-testable with a fake (no live DB), mirroring internal/relays.
type Store interface {
	Upsert(ctx context.Context, userID string, refreshEnc []byte, email string) error
	Get(ctx context.Context, userID string) (refreshEnc []byte, email string, err error)
	Delete(ctx context.Context, userID string) error
}

// ErrNotFound = user has no stored refresh token (→ client shows Connect).
var ErrNotFound = sql.ErrNoRows

// SQLStore is the CRDB/Postgres implementation (writable DSN, own scoped user).
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// Migrate creates the table if absent (idempotent — safe on every boot, like the hub).
func (s *SQLStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS google_drive_tokens (
			user_id     STRING PRIMARY KEY,
			refresh_enc BYTES NOT NULL,
			email       STRING NOT NULL,
			created_at  TIMESTAMPTZ DEFAULT now(),
			updated_at  TIMESTAMPTZ DEFAULT now()
		)`)
	return err
}

func (s *SQLStore) Upsert(ctx context.Context, userID string, refreshEnc []byte, email string) error {
	_, err := s.db.ExecContext(ctx, `
		UPSERT INTO google_drive_tokens (user_id, refresh_enc, email, updated_at)
		VALUES ($1, $2, $3, now())`, userID, refreshEnc, email)
	return err
}

func (s *SQLStore) Get(ctx context.Context, userID string) ([]byte, string, error) {
	var enc []byte
	var email string
	err := s.db.QueryRowContext(ctx,
		`SELECT refresh_enc, email FROM google_drive_tokens WHERE user_id=$1`, userID).
		Scan(&enc, &email)
	return enc, email, err // sql.ErrNoRows == ErrNotFound
}

func (s *SQLStore) Delete(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM google_drive_tokens WHERE user_id=$1`, userID)
	return err
}
