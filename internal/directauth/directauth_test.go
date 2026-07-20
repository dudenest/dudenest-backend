package directauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dudenest/dudenest-backend/internal/auth"
)

const testKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // base64 of 32 bytes

// ─── fake store (multi-konto) ────────────────────────────────────────────────
type fakeStore struct {
	accounts map[string]Account
	deleted  []string
}

func newFakeStore() *fakeStore { return &fakeStore{accounts: map[string]Account{}} }

func (f *fakeStore) Upsert(_ context.Context, a Account) error { f.accounts[a.AccountID] = a; return nil }
func (f *fakeStore) Get(_ context.Context, id string) (Account, error) {
	a, ok := f.accounts[id]
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}
func (f *fakeStore) ListByUser(_ context.Context, userID string) ([]Account, error) {
	var out []Account
	for _, a := range f.accounts {
		if a.UserID == userID {
			out = append(out, Account{AccountID: a.AccountID, UserID: a.UserID, Provider: a.Provider, Email: a.Email})
		}
	}
	return out, nil
}
func (f *fakeStore) Delete(_ context.Context, id string) error {
	delete(f.accounts, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func newTestHandler(t *testing.T, store Store) *Handler {
	t.Helper()
	h, err := NewHandler(store, testKey, "cid", "secret",
		"https://api.dudenest.com/auth/callback", "https://dudenest.com", "dev-secret-change-in-prod")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func googleJWT(t *testing.T, sub string) string {
	t.Helper()
	tok, err := auth.IssueJWT(auth.Claims{Sub: sub, Email: "me@gmail.com", Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mockGoogle MUSI być wołane PRZED newTestHandler (NewHandler czyta URL-e do providerConfig).
func mockGoogle(t *testing.T, refresh, userEmail string, invalidGrant bool) {
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
}

// ─── crypto / state ──────────────────────────────────────────────────────────
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
	if _, err := NewCipher("dG9vLXNob3J0"); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
}

func TestStateSignVerify(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	s := h.signState("google:1", "google", "https://dudenest.com")
	d, ok := h.verifyState(s)
	if !ok || d.Sub != "google:1" || d.Provider != "google" {
		t.Fatalf("verify: ok=%v d=%+v", ok, d)
	}
	if _, ok := h.verifyState(s + "x"); ok {
		t.Fatal("tampered state must fail")
	}
}

// ─── StartConnect ────────────────────────────────────────────────────────────
func TestStartConnectRedirect(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	r := httptest.NewRequest("GET", "/auth/google/connect?token="+googleJWT(t, "google:1")+"&return_url=https://dudenest.com/x", nil)
	w := httptest.NewRecorder()
	h.Start("google")(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d", w.Code)
	}
	loc := w.Header().Get("Location")
	for _, want := range []string{"access_type=offline", "prompt=consent", "drive.file", "callback%2Fgoogle%2Fdrive", "state="} {
		if !strings.Contains(loc, want) {
			t.Errorf("redirect missing %q: %s", want, loc)
		}
	}
}

func TestStartConnectUnknownProvider(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	r := httptest.NewRequest("GET", "/auth/mega/connect?token="+googleJWT(t, "google:1"), nil)
	w := httptest.NewRecorder()
	h.Start("mega")(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown provider should be 404, got %d", w.Code)
	}
}

// ─── Callback ────────────────────────────────────────────────────────────────
func TestCallbackStoresAccount(t *testing.T) {
	mockGoogle(t, "refresh-xyz", "me@gmail.com", false)
	store := newFakeStore()
	h := newTestHandler(t, store)
	state := h.signState("google:1", "google", "https://dudenest.com")
	r := httptest.NewRequest("GET", "/auth/callback/google/drive?code=CODE&state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback("google")(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	acc, ok := store.accounts["google:me@gmail.com"]
	if !ok {
		t.Fatal("account not stored under provider:email key")
	}
	if acc.UserID != "google:1" || acc.Provider != "google" {
		t.Errorf("bad account: %+v", acc)
	}
	if strings.Contains(string(acc.RefreshEnc), "refresh-xyz") {
		t.Fatal("refresh token stored in plaintext!")
	}
}

// ─── ListAccounts ────────────────────────────────────────────────────────────
func TestListAccounts(t *testing.T) {
	store := newFakeStore()
	store.accounts["google:a@x.com"] = Account{AccountID: "google:a@x.com", UserID: "u1", Provider: "google", Email: "a@x.com"}
	store.accounts["google:b@x.com"] = Account{AccountID: "google:b@x.com", UserID: "u1", Provider: "google", Email: "b@x.com"}
	store.accounts["google:c@x.com"] = Account{AccountID: "google:c@x.com", UserID: "u2", Provider: "google", Email: "c@x.com"}
	h := newTestHandler(t, store)
	r := httptest.NewRequest("GET", "/api/v1/direct/accounts", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u1"))
	w := httptest.NewRecorder()
	h.ListAccounts(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	var body struct {
		Accounts []map[string]string `json:"accounts"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.Accounts) != 2 { // tylko konta u1
		t.Fatalf("expected 2 accounts for u1, got %d", len(body.Accounts))
	}
}

// ─── AccountToken ────────────────────────────────────────────────────────────
func TestAccountTokenHappy(t *testing.T) {
	mockGoogle(t, "", "me@gmail.com", false)
	h := newTestHandler(t, newFakeStore())
	sealed, _ := h.encrypt([]byte("refresh-xyz"))
	store := newFakeStore()
	store.accounts["google:me@gmail.com"] = Account{AccountID: "google:me@gmail.com", UserID: "u1", Provider: "google", Email: "me@gmail.com", RefreshEnc: sealed}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/accounts/google:me@gmail.com/token", nil)
	r.SetPathValue("id", "google:me@gmail.com")
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u1"))
	w := httptest.NewRecorder()
	h.AccountToken(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access-123") {
		t.Fatalf("expected 200 access-123, got %d %s", w.Code, w.Body.String())
	}
}

func TestAccountTokenWrongUser(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	sealed, _ := h.encrypt([]byte("r"))
	store := newFakeStore()
	store.accounts["google:me@gmail.com"] = Account{AccountID: "google:me@gmail.com", UserID: "u1", Provider: "google", Email: "me@gmail.com", RefreshEnc: sealed}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/accounts/google:me@gmail.com/token", nil)
	r.SetPathValue("id", "google:me@gmail.com")
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u2")) // NIE właściciel
	w := httptest.NewRecorder()
	h.AccountToken(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cudze konto → 404, got %d", w.Code)
	}
}

func TestAccountTokenInvalidGrantDeletes(t *testing.T) {
	mockGoogle(t, "", "me@gmail.com", true)
	h := newTestHandler(t, newFakeStore())
	sealed, _ := h.encrypt([]byte("revoked"))
	store := newFakeStore()
	store.accounts["google:me@gmail.com"] = Account{AccountID: "google:me@gmail.com", UserID: "u1", Provider: "google", Email: "me@gmail.com", RefreshEnc: sealed}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/accounts/google:me@gmail.com/token", nil)
	r.SetPathValue("id", "google:me@gmail.com")
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u1"))
	w := httptest.NewRecorder()
	h.AccountToken(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("invalid_grant → 404, got %d", w.Code)
	}
	if len(store.deleted) != 1 {
		t.Fatal("revoked account must be deleted")
	}
}

// ─── GoogleTokenLegacy (backward compat) ─────────────────────────────────────
func TestGoogleTokenLegacy(t *testing.T) {
	mockGoogle(t, "", "me@gmail.com", false)
	h := newTestHandler(t, newFakeStore())
	sealed, _ := h.encrypt([]byte("refresh-xyz"))
	store := newFakeStore()
	store.accounts["google:me@gmail.com"] = Account{AccountID: "google:me@gmail.com", UserID: "u1", Provider: "google", Email: "me@gmail.com", RefreshEnc: sealed}
	h.Store = store
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u1"))
	w := httptest.NewRecorder()
	h.GoogleTokenLegacy(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access-123") {
		t.Fatalf("legacy token: %d %s", w.Code, w.Body.String())
	}
}

func TestGoogleTokenLegacyNotConnected(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	r := httptest.NewRequest("GET", "/api/v1/direct/google/token", nil)
	r.Header.Set("Authorization", "Bearer "+googleJWT(t, "u1"))
	w := httptest.NewRecorder()
	h.GoogleTokenLegacy(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("no account → 404, got %d", w.Code)
	}
}

func TestNoAuth(t *testing.T) {
	h := newTestHandler(t, newFakeStore())
	r := httptest.NewRequest("GET", "/api/v1/direct/accounts", nil)
	w := httptest.NewRecorder()
	h.ListAccounts(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth → 401, got %d", w.Code)
	}
}

// compile-time: SQLStore satisfies Store
var _ Store = (*SQLStore)(nil)
