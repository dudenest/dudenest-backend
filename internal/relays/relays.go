// Package relays serves the per-user relay list directly from CRDB, decoupling
// Flutter's /api/v1/relays from the dudenest-hub service (HUB-DECOUPLING Phase 1).
// Today the backend proxies /api/v1/relays → hub /user/relays; when the hub is
// down (s363 incident) the whole flow 5xx's and Flutter falls back to a default
// relay URL. Reading CRDB directly here removes the hub as a SPOF for that path.
//
// CONTRACT: the JSON response MUST be byte-identical to dudenest-hub
// handleListRelays (server.go), and relay_token MUST use the exact same HMAC
// scheme (key=relay_secret, msg=userID+":"+expiry) — otherwise relays reject
// backend-issued tokens and every relay breaks. userID is the JWT `sub` claim
// verbatim (same value the hub signs with); do NOT transform it (no email, no
// stripping the "google:" prefix).
package relays

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Relay mirrors the columns the hub selects in GetRelaysByUser.
type Relay struct {
	RelayID      string
	UserID       string
	HeadscaleIP  string
	RelayVersion string
	RelaySecret  string // HMAC key — NEVER serialized to Flutter
	RelayURL     string
	RegisteredAt time.Time
	LastBackupAt *time.Time
	LastSeenAt   *time.Time
}

// Store is the read side needed by the handler; SQLStore is the CRDB impl.
type Store interface {
	ListByUser(ctx context.Context, userID string) ([]Relay, error)
}

// ctxKey is unexported so only this package's WithUserID can set the value.
type ctxKey struct{}

// WithUserID stashes the authenticated JWT sub claim for MyRelaysHandler.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKey{}, userID)
}

// UserIDFromCtx returns the userID set by WithUserID, or "" if absent.
func UserIDFromCtx(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}

// tokenTTL matches dudenest-hub handleListRelays (1 hour).
const tokenTTL = time.Hour

// signToken builds the Layer-3 relay token. Kept separate from SignRelayToken so
// tests can pin `expiry` and compare against the hub's byte-for-byte scheme.
func signToken(relaySecret, userID string, expiry int64) string {
	expiryStr := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha256.New, []byte(relaySecret))
	mac.Write([]byte(userID + ":" + expiryStr))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) + "." + expiryStr
}

// SignRelayToken issues a short-lived HMAC token; identical to hub server.go.
func SignRelayToken(relaySecret, userID string, ttl time.Duration) string {
	return signToken(relaySecret, userID, time.Now().Add(ttl).Unix())
}

// relaySummary is the wire shape; field order/names match hub handleListRelays.
type relaySummary struct {
	RelayID      string  `json:"relay_id"`
	HeadscaleIP  string  `json:"headscale_ip"`
	RelayVersion string  `json:"relay_version"`
	RelayURL     string  `json:"relay_url"`
	RelayToken   string  `json:"relay_token"`
	RegisteredAt string  `json:"registered_at"`
	LastBackupAt *string `json:"last_backup_at,omitempty"`
	LastSeenAt   *string `json:"last_seen_at,omitempty"`
}

const tsLayout = "2006-01-02T15:04:05Z" // same layout the hub formats with

// MyRelaysHandler serves GET /api/v1/relays from CRDB. userID comes from context
// (set by requireAuth via WithUserID) so the handler stays auth-mechanism-agnostic.
func MyRelaysHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"GET only"}`, http.StatusMethodNotAllowed)
			return
		}
		userID := UserIDFromCtx(r.Context())
		if userID == "" { // requireAuth must inject it; guard against misconfig
			http.Error(w, `{"error":"missing user context"}`, http.StatusUnauthorized)
			return
		}
		rels, err := store.ListByUser(r.Context(), userID)
		if err != nil {
			http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
			return
		}
		out := make([]relaySummary, 0, len(rels))
		for _, rel := range rels {
			rs := relaySummary{
				RelayID:      rel.RelayID,
				HeadscaleIP:  rel.HeadscaleIP,
				RelayVersion: rel.RelayVersion,
				RelayURL:     rel.RelayURL,
				RelayToken:   SignRelayToken(rel.RelaySecret, userID, tokenTTL),
				RegisteredAt: rel.RegisteredAt.Format(tsLayout),
			}
			if rel.LastBackupAt != nil { t := rel.LastBackupAt.Format(tsLayout); rs.LastBackupAt = &t }
			if rel.LastSeenAt != nil { t := rel.LastSeenAt.Format(tsLayout); rs.LastSeenAt = &t }
			out = append(out, rs)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"relays": out}) //nolint:errcheck
	}
}
