package directauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dudenest/dudenest-backend/internal/auth"
)

const testKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // base64 of 32 bytes

// ─── fake store ──────────────────────────────────────────────────────────────
type fakeStore struct {
	enc     []byte
	email   string
	present bool
	deleted bool
}

func (f *fakeStore) Upsert(_ context.Context, _ string, enc []byte, email string) error {
	f.enc, f.email, f.present = enc, email, true
	return nil
}
func (f *fakeStore) Get(_ context.Context, _ string) ([]byte, string, error) {
	if !f.present {
		return nil, "", ErrNotFound
	}
	return f.enc, f.email, nil
}
func (f *fakeStore) Delete(_ context.Context, _ string) error { f.deleted = true; f.present = false; return nil }

func newTestHandler(t *testing.T, store Store) *Handler {
	t.Helper()
	h, err := NewHandler(store, testKey, "cid", "secret",
		"https://api.dudenest.com/auth/callback/google/drive", "https://dudenest.com", "dev-secret-change-in-prod")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func googleJWT(t *testing.T) string {
	t.Helper()
	tok, err := auth.IssueJWT(auth.Claims{Sub: "google:1", Email: "me@gmail.com", Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ─── crypto ──────────────────────────────────────────────────────────────────
func TestCryptoRoundTrip(t *testing.T) {
	a, err := NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := Encrypt(a, []byte("refresh-token-xyz"))
	pt, err := Decrypt(a, ct)
	if err != nil || string(pt) != "refresh-token-xyz" {
		t.Fatalf("round-trip: pt=%q err=%v", pt, err)
	}
}

func TestNewCipherBadKey(t *testing.T) {
	if _, err := NewCipher("dG9vLXNob3J0"); err == nil { // "too-short" base64 → not 32 bytes
		t.Fatal("expected error for non-32-byte key")
	}
}

func TestStateSignVerify(t *testing.T) {
	h := newTestHandler(t, &fakeStore{})
	s := h.signState("google:1", "me@gmail.com", "https://dudenest.com")
	d, ok := h.verifyState(s)
	if !ok || d.Sub != "google:1" || d.Email != "me@gmail.com" {
		t.Fatalf("verify: ok=%v d=%+v", ok, d)
	}
	if _, ok := h.verifyState(s + "x"); ok {
		t.Fatal("tampered state must fail")
	}
}

// ─── StartDrive ──────────────────────────────────────────────────────────────
func TestStartDriveRedirect(t *testing.T) {
	h := newTestHandler(t, &fakeStore{})
	r := httptest.NewRequest("GET", "/auth/google/drive?token="+googleJWT(t)+"&return_url=https://dudenest.com/x", nil)
	w := httptest.NewRecorder()
	h.StartDrive(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d", w.Code)
	}
	loc := w.Header().Get("Location")
	for _, want := range []string{"access_type=offline", "prompt=consent", "drive.file", "state="} {
		if !strings.Contains(loc, want) {
			t.Errorf("redirect missing %q: %s", want, loc)
		}
	}
}

func TestStartDriveNonGoogle(t *testing.T) {
	h := newTestHandler(t, &fakeStore{})
	tok, _ := auth.IssueJWT(auth.Claims{Sub: "github:1", Email: "x@y.z", Provider: "github"})
	r := httptest.NewRequest("GET", "/auth/google/drive?token="+tok, nil)
	w := httptest.NewRecorder()
	h.StartDrive(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("non-google should be 400, got %d", w.Code)
	}
}

// ─── Callback ────────────────────────────────────────────────────────────────
func mockGoogle(t *testing.T, refresh, userEmail string, invalidGrant bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			if invalidGrant {
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-123", "expires_in": 3599})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "access-abc", "refresh_token": refresh})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"email": userEmail})
	})
	srv := httptest.NewServer(mux)
	googleTokenURL = srv.URL + "/token"
	googleUserinfoURL = srv.URL + "/userinfo"
	t.Cleanup(srv.Close)
	return srv
}

func TestCallbackHappyPath(t *testing.T) {
	mockGoogle(t, "refresh-xyz", "me@gmail.com", false)
	store := &fakeStore{}
	h := newTestHandler(t, store)
	state := h.signState("google:1", "me@gmail.com", "https://dudenest.com")
	r := httptest.NewRequest("GET", "/auth/callback/google/drive?code=CODE&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.CallbackDrive(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	if !store.present {
		t.Fatal("refresh token not stored")
	}
	if !strings.Contains(w.Header().Get("Location"), "drive=connected") {
		t.Errorf("missing drive=connected: %s", w.Header().Get("Location"))
	}
	// stored blob must be encrypted (not plaintext)
	if strings.Contains(string(store.enc), "refresh-xyz") {
		t.Fatal("refresh token stored in plaintext!")
	}
}

func TestCallbackAccountMismatch(t *testing.T) {
	mockGoogle(t, "refresh-xyz", "someone-else@gmail.com", false) // userinfo != state email
	store := &fakeStore{}
	h := newTestHandler(t, store)
	state := h.signState("google:1", "me@gmail.com", "https://dudenest.com")
	r := httptest.NewRequest("GET", "/auth/callback/google/drive?code=CODE&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.CallbackDrive(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("mismatch should be 403, got %d", w.Code)
	}
	if store.present {
		t.Fatal("must NOT store on account mismatch")
	}
}

// ─── Token ───────────────────────────────────────────────────────────────────
func TestTokenNotConnected(t *testing.T) {
	h := newTestHandler(t, &fakeStore{}) // empty
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t))
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_connected") {
		t.Fatalf("expected 404 not_connected, got %d %s", w.Code, w.Body.String())
	}
}

func TestTokenHappyPath(t *testing.T) {
	mockGoogle(t, "", "me@gmail.com", false)
	h := newTestHandler(t, &fakeStore{})
	sealed, _ := h.encrypt([]byte("refresh-xyz"))
	store := &fakeStore{enc: sealed, email: "me@gmail.com", present: true}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t))
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access-123") {
		t.Fatalf("expected 200 with access token, got %d %s", w.Code, w.Body.String())
	}
}

func TestTokenInvalidGrantDeletes(t *testing.T) {
	mockGoogle(t, "", "me@gmail.com", true) // refresh → invalid_grant
	h := newTestHandler(t, &fakeStore{})
	sealed, _ := h.encrypt([]byte("revoked-refresh"))
	store := &fakeStore{enc: sealed, email: "me@gmail.com", present: true}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t))
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("invalid_grant should → 404, got %d", w.Code)
	}
	if !store.deleted {
		t.Fatal("revoked token must be deleted (force reconnect)")
	}
}

func TestTokenNoAuth(t *testing.T) {
	h := newTestHandler(t, &fakeStore{})
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth should → 401, got %d", w.Code)
	}
}

// compile-time: SQLStore satisfies Store
var _ Store = (*SQLStore)(nil)
