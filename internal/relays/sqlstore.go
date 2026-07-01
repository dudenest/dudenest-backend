package relays

import (
	"context"
	"database/sql"
)

// SQLStore reads relays from CRDB via database/sql. The lib/pq driver is
// registered by the caller (blank import) so this file stays driver-agnostic
// and unit-testable without a live database.
type SQLStore struct{ db *sql.DB }

// NewSQLStore wraps an already-open *sql.DB (postgres/CRDB).
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// listByUserQuery mirrors dudenest-hub store.go GetRelaysByUser column order.
const listByUserQuery = `SELECT relay_id,user_id,headscale_ip,relay_version,relay_secret,relay_url,registered_at,last_backup_at,last_seen_at ` +
	`FROM relays WHERE user_id=$1 ORDER BY registered_at DESC`

// ListByUser returns the caller's relays, newest first (same order as the hub).
func (s *SQLStore) ListByUser(ctx context.Context, userID string) ([]Relay, error) {
	rows, err := s.db.QueryContext(ctx, listByUserQuery, userID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		var r Relay
		var headscaleIP, relayVersion sql.NullString // nullable for legacy/provisioned rows
		if err := rows.Scan(&r.RelayID, &r.UserID, &headscaleIP, &relayVersion,
			&r.RelaySecret, &r.RelayURL, &r.RegisteredAt, &r.LastBackupAt, &r.LastSeenAt); err != nil {
			return nil, err
		}
		r.HeadscaleIP = headscaleIP.String
		r.RelayVersion = relayVersion.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// Ping verifies CRDB connectivity (used by the hub-health / readiness path).
func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
