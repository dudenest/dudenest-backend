package directauth

import (
	"context"
	"database/sql"
)

// Account = jedno podłączone konto cloud usera Dudenest (provider + email + zaszyfrowany refresh token).
type Account struct {
	AccountID  string // "provider:email", np. "google:me@gmail.com"
	UserID     string // Dudenest Claims.Sub
	Provider   string // google | onedrive | dropbox | mega
	Email      string
	RefreshEnc []byte // AES-256-GCM(refresh_token); PUSTE w wynikach ListByUser
}

// Store — multi-konto (jeden user może mieć wiele kont, różnych providerów).
type Store interface {
	Upsert(ctx context.Context, a Account) error
	Get(ctx context.Context, accountID string) (Account, error) // ErrNotFound gdy brak
	ListByUser(ctx context.Context, userID string) ([]Account, error) // bez RefreshEnc
	Delete(ctx context.Context, accountID string) error
}

// ErrNotFound = brak konta (→ klient pokazuje „Connect").
var ErrNotFound = sql.ErrNoRows

// SQLStore — CRDB/Postgres (writable, scoped user backend_drive).
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// Migrate tworzy tabelę (idempotentnie) i migruje stare 1-kontowe wiersze z google_drive_tokens.
func (s *SQLStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS direct_accounts (
			account_id  STRING PRIMARY KEY,
			user_id     STRING NOT NULL,
			provider    STRING NOT NULL,
			email       STRING NOT NULL,
			refresh_enc BYTES NOT NULL,
			created_at  TIMESTAMPTZ DEFAULT now(),
			updated_at  TIMESTAMPTZ DEFAULT now(),
			INDEX (user_id)
		)`); err != nil {
		return err
	}
	// Best-effort migracja legacy (google_drive_tokens → direct_accounts). Idempotentne; ignorujemy
	// błąd gdy stara tabela nie istnieje albo wiersze już zmigrowane.
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO direct_accounts (account_id, user_id, provider, email, refresh_enc)
		SELECT 'google:'||email, user_id, 'google', email, refresh_enc FROM google_drive_tokens
		ON CONFLICT (account_id) DO NOTHING`)
	return nil
}

func (s *SQLStore) Upsert(ctx context.Context, a Account) error {
	_, err := s.db.ExecContext(ctx, `
		UPSERT INTO direct_accounts (account_id, user_id, provider, email, refresh_enc, updated_at)
		VALUES ($1,$2,$3,$4,$5, now())`, a.AccountID, a.UserID, a.Provider, a.Email, a.RefreshEnc)
	return err
}

func (s *SQLStore) Get(ctx context.Context, accountID string) (Account, error) {
	var a Account
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id,user_id,provider,email,refresh_enc FROM direct_accounts WHERE account_id=$1`,
		accountID).Scan(&a.AccountID, &a.UserID, &a.Provider, &a.Email, &a.RefreshEnc)
	return a, err
}

func (s *SQLStore) ListByUser(ctx context.Context, userID string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT account_id,provider,email FROM direct_accounts WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a := Account{UserID: userID}
		if err := rows.Scan(&a.AccountID, &a.Provider, &a.Email); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) Delete(ctx context.Context, accountID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM direct_accounts WHERE account_id=$1`, accountID)
	return err
}
