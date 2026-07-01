package relays

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// fakeStore lets us drive the handler without a database.
type fakeStore struct {
	relays []Relay
	err    error
}

func (f *fakeStore) ListByUser(_ context.Context, _ string) ([]Relay, error) {
	return f.relays, f.err
}

var _ Store = (*fakeStore)(nil) // compile-time interface check

// hubToken recomputes the token exactly as dudenest-hub handleListRelays does
// (key=relay_secret, msg=userID+":"+expiry). If signToken ever drifts from this,
// relays would reject backend-issued tokens — this is the cutover safety net.
func hubToken(relaySecret, userID string, expiry int64) string {
	expiryStr := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha256.New, []byte(relaySecret))
	mac.Write([]byte(userID + ":" + expiryStr))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) + "." + expiryStr
}

func TestSignToken_MatchesHubScheme(t *testing.T) {
	const secret, userID = "s3cr3t-relay-key", "google:104335867324508933233"
	expiry := int64(1900000000) // pinned so both sides compute identically
	got := signToken(secret, userID, expiry)
	want := hubToken(secret, userID, expiry)
	if got != want {
		t.Fatalf("token mismatch vs hub scheme:\n got=%s\nwant=%s", got, want)
	}
}

func TestSignRelayToken_RoundTripExpiry(t *testing.T) {
	before := time.Now().Add(tokenTTL).Unix()
	tok := SignRelayToken("k", "u", tokenTTL)
	after := time.Now().Add(tokenTTL).Unix()
	// token = base64sig + "." + expiry — expiry must land within [before, after]
	dot := len(tok) - len(strconv.FormatInt(after, 10))
	exp, err := strconv.ParseInt(tok[dot:], 10, 64)
	if err != nil || exp < before || exp > after {
		t.Fatalf("expiry %d not in [%d,%d] (err=%v)", exp, before, after, err)
	}
}

func doList(t *testing.T, store Store, withUser bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/relays", nil)
	if withUser {
		req = req.WithContext(WithUserID(req.Context(), "google:104335867324508933233"))
	}
	w := httptest.NewRecorder()
	MyRelaysHandler(store).ServeHTTP(w, req)
	return w
}

func TestMyRelaysHandler_HappyPath(t *testing.T) {
	lastSeen := time.Date(2026, 6, 25, 4, 59, 53, 0, time.UTC)
	store := &fakeStore{relays: []Relay{{
		RelayID: "relay-d3ee44be", UserID: "google:104335867324508933233",
		HeadscaleIP: "100.64.0.7", RelayVersion: "0.23.9", RelaySecret: "topsecret",
		RelayURL: "https://relay-d3ee44be.dudenest.com",
		RegisteredAt: time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC), LastSeenAt: &lastSeen,
	}}}
	w := doList(t, store, true)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Relays []map[string]any `json:"relays"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.Relays) != 1 {
		t.Fatalf("relays len = %d, want 1", len(resp.Relays))
	}
	r := resp.Relays[0]
	if r["relay_url"] != "https://relay-d3ee44be.dudenest.com" {
		t.Errorf("relay_url = %v", r["relay_url"])
	}
	if _, ok := r["relay_secret"]; ok {
		t.Error("relay_secret leaked to Flutter — must never be serialized")
	}
	// relay_token must validate against the hub scheme for the same expiry.
	tok, _ := r["relay_token"].(string)
	dot := len(tok) - 1
	for dot >= 0 && tok[dot] != '.' {
		dot--
	}
	exp, err := strconv.ParseInt(tok[dot+1:], 10, 64)
	if err != nil {
		t.Fatalf("token expiry parse: %v", err)
	}
	if tok != hubToken("topsecret", "google:104335867324508933233", exp) {
		t.Error("relay_token does not match hub HMAC scheme")
	}
}

func TestMyRelaysHandler_NoUserContext(t *testing.T) {
	if w := doList(t, &fakeStore{}, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestMyRelaysHandler_EmptyListIsArray(t *testing.T) {
	w := doList(t, &fakeStore{relays: nil}, true)
	if body := w.Body.String(); body != "{\"relays\":[]}\n" {
		t.Fatalf("empty list body = %q, want {\"relays\":[]} (never null)", body)
	}
}

func TestMyRelaysHandler_StoreError(t *testing.T) {
	w := doList(t, &fakeStore{err: errors.New("crdb down")}, true)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
