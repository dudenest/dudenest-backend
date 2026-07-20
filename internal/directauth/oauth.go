package directauth

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dudenest/dudenest-backend/internal/auth"
)

// Google endpoints — package vars so tests can point them at httptest servers.
var (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserinfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	googleRevokeURL   = "https://oauth2.googleapis.com/revoke"
	httpClient        = http.DefaultClient
)

// providerConfig — per-provider OAuth. MP1 = tylko google; MP2+ dodaje onedrive/dropbox/mega.
type providerConfig struct {
	authURL, tokenURL, userinfoURL, revokeURL string
	scope, clientID, clientSecret             string
}

// Handler — direct-mode OAuth, MULTI-KONTO / multi-provider.
type Handler struct {
	Store        Store
	AppURL       string // https://dudenest.com — open-redirect guard
	RedirectBase string // https://api.dudenest.com/auth/callback  (+ "/{provider}/drive")
	stateSecret  []byte
	aead         cipher.AEAD
	providers    map[string]providerConfig
}

// NewHandler buduje Handler. Dla MP1 rejestruje providera google (URL-e z package vars → testowalne).
func NewHandler(store Store, encKeyB64, googleClientID, googleClientSecret, redirectBase, appURL, jwtSecret string) (*Handler, error) {
	aead, err := NewCipher(encKeyB64)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Store: store, AppURL: appURL, RedirectBase: redirectBase,
		stateSecret: []byte(jwtSecret), aead: aead,
		providers: map[string]providerConfig{
			"google": {
				authURL: googleAuthURL, tokenURL: googleTokenURL,
				userinfoURL: googleUserinfoURL, revokeURL: googleRevokeURL,
				scope:    "openid email https://www.googleapis.com/auth/drive.file",
				clientID: googleClientID, clientSecret: googleClientSecret,
			},
		},
	}, nil
}

func (h *Handler) encrypt(pt []byte) ([]byte, error) { return Encrypt(h.aead, pt) }
func (h *Handler) decrypt(ct []byte) ([]byte, error) { return Decrypt(h.aead, ct) }
func (h *Handler) redirectURI(provider string) string { return h.RedirectBase + "/" + provider + "/drive" }

// ─── State (podpisany, krótki): niesie user + provider + return_url przez redirect ──

type stateData struct {
	Sub      string `json:"s"`
	Provider string `json:"p"`
	Ret      string `json:"r"`
	Exp      int64  `json:"x"`
}

func (h *Handler) signState(sub, provider, ret string) string {
	raw, _ := json.Marshal(stateData{Sub: sub, Provider: provider, Ret: ret, Exp: time.Now().Add(10 * time.Minute).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + h.hmac(payload)
}

func (h *Handler) verifyState(s string) (stateData, bool) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(h.hmac(parts[0])), []byte(parts[1])) {
		return stateData{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return stateData{}, false
	}
	var d stateData
	if json.Unmarshal(raw, &d) != nil || time.Now().Unix() > d.Exp {
		return stateData{}, false
	}
	return d, true
}

func (h *Handler) hmac(msg string) string {
	m := hmac.New(sha256.New, h.stateSecret)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (h *Handler) safeReturn(ret string) string {
	if ret != "" && (strings.HasPrefix(ret, h.AppURL) || strings.HasPrefix(ret, "https://app.dudenest.com")) {
		return ret
	}
	return h.AppURL
}

// ─── Handlers ──────────────────────────────────────────────────────────────

// Start zwraca handler dla USTALONEGO providera (trasy legacy/jawne). StartConnect czyta {provider} z path.
func (h *Handler) Start(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { h.startConnect(w, r, provider) }
}
func (h *Handler) StartConnect(w http.ResponseWriter, r *http.Request) {
	h.startConnect(w, r, r.PathValue("provider"))
}

// startConnect: redirect do zgody providera (offline → refresh token).
func (h *Handler) startConnect(w http.ResponseWriter, r *http.Request, provider string) {
	pc, ok := h.providers[provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	claims, err := auth.ValidateJWT(r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ret := h.safeReturn(r.URL.Query().Get("return_url"))
	params := url.Values{
		"client_id":              {pc.clientID},
		"redirect_uri":           {h.redirectURI(provider)},
		"response_type":          {"code"},
		"scope":                  {pc.scope},
		"access_type":            {"offline"},
		"prompt":                 {"consent"}, // wymusza refresh token + świadomy wybór konta (multi-konto)
		"include_granted_scopes": {"true"},
		"state":                  {h.signState(claims.Sub, provider, ret)},
	}
	http.Redirect(w, r, pc.authURL+"?"+params.Encode(), http.StatusFound)
}

// Callback zwraca handler dla USTALONEGO providera (trasy legacy/jawne). CallbackConnect czyta {provider}.
func (h *Handler) Callback(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { h.callbackConnect(w, r, provider) }
}
func (h *Handler) CallbackConnect(w http.ResponseWriter, r *http.Request) {
	h.callbackConnect(w, r, r.PathValue("provider"))
}

// callbackConnect: exchange kodu + zapis KONTA (nie nadpisuje istniejących — multi-konto).
func (h *Handler) callbackConnect(w http.ResponseWriter, r *http.Request, provider string) {
	pc, ok := h.providers[provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	st, ok := h.verifyState(r.URL.Query().Get("state"))
	if !ok || st.Provider != provider {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	tok, err := h.exchangeCode(provider, pc, r.URL.Query().Get("code"))
	if err != nil || tok.AccessToken == "" {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	email := h.userinfoEmail(pc, tok.AccessToken)
	if email == "" {
		http.Error(w, "could not read account email", http.StatusBadGateway)
		return
	}
	if tok.RefreshToken == "" {
		http.Error(w, "no refresh token returned (retry consent)", http.StatusBadGateway)
		return
	}
	sealed, err := h.encrypt([]byte(tok.RefreshToken))
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}
	acc := Account{AccountID: provider + ":" + email, UserID: st.Sub, Provider: provider, Email: email, RefreshEnc: sealed}
	if err := h.Store.Upsert(r.Context(), acc); err != nil {
		log.Printf("directauth: upsert failed: %v", err)
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	log.Printf("directauth: connected %s for %s", acc.AccountID, st.Sub)
	sep := "?"
	if strings.Contains(st.Ret, "?") {
		sep = "&"
	}
	http.Redirect(w, r, st.Ret+sep+"drive=connected", http.StatusFound)
}

// ListAccounts: GET /api/v1/direct/accounts → [{account_id, provider, email}] usera.
func (h *Handler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accs, err := h.Store.ListByUser(r.Context(), claims.Sub)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]string, 0, len(accs))
	for _, a := range accs {
		out = append(out, map[string]string{"account_id": a.AccountID, "provider": a.Provider, "email": a.Email})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

// AccountToken: GET /api/v1/direct/accounts/{id}/token → świeży access token dla konta.
func (h *Handler) AccountToken(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	acc, err := h.Store.Get(r.Context(), r.PathValue("id"))
	if err == ErrNotFound || (err == nil && acc.UserID != claims.Sub) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_connected"}) // cudze konto = jak brak
		return
	} else if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	h.mintAndWrite(w, r, acc)
}

// GoogleTokenLegacy: GET /api/v1/direct/google/token — backward-compat (stary Flutter, 1 konto).
// Bierze PIERWSZE konto google usera. Usunąć po migracji klientów na endpointy multi-konto.
func (h *Handler) GoogleTokenLegacy(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accs, err := h.Store.ListByUser(r.Context(), claims.Sub)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	for _, a := range accs {
		if a.Provider == "google" {
			full, err := h.Store.Get(r.Context(), a.AccountID)
			if err != nil {
				http.Error(w, "store error", http.StatusInternalServerError)
				return
			}
			h.mintAndWrite(w, r, full)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_connected"})
}

// mintAndWrite: refresh → access token; invalid_grant → skasuj konto + 404.
func (h *Handler) mintAndWrite(w http.ResponseWriter, r *http.Request, acc Account) {
	pc, ok := h.providers[acc.Provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusInternalServerError)
		return
	}
	refresh, err := h.decrypt(acc.RefreshEnc)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusInternalServerError)
		return
	}
	access, expiresIn, invalid := h.refreshAccess(pc, string(refresh))
	if invalid {
		_ = h.Store.Delete(r.Context(), acc.AccountID) // odwołany → wymuś reconnect
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_connected"})
		return
	}
	if access == "" {
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "expires_in": expiresIn, "email": acc.Email, "provider": acc.Provider,
	})
}

// DeleteAccount: DELETE /api/v1/direct/accounts/{id} → revoke + delete (tylko własne).
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if acc, err := h.Store.Get(r.Context(), id); err == nil && acc.UserID == claims.Sub {
		if pc, ok := h.providers[acc.Provider]; ok && pc.revokeURL != "" {
			if refresh, e := h.decrypt(acc.RefreshEnc); e == nil {
				_, _ = httpClient.PostForm(pc.revokeURL, url.Values{"token": {string(refresh)}})
			}
		}
		_ = h.Store.Delete(r.Context(), id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Google calls (per providerConfig) ───────────────────────────────────────

type googleToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func (h *Handler) exchangeCode(provider string, pc providerConfig, code string) (googleToken, error) {
	return postToken(pc.tokenURL, url.Values{
		"code": {code}, "client_id": {pc.clientID}, "client_secret": {pc.clientSecret},
		"redirect_uri": {h.redirectURI(provider)}, "grant_type": {"authorization_code"},
	})
}

// refreshAccess: (access, expiresIn, invalidGrant).
func (h *Handler) refreshAccess(pc providerConfig, refresh string) (string, int, bool) {
	tok, err := postToken(pc.tokenURL, url.Values{
		"client_id": {pc.clientID}, "client_secret": {pc.clientSecret},
		"refresh_token": {refresh}, "grant_type": {"refresh_token"},
	})
	if err != nil {
		return "", 0, false
	}
	if tok.Error == "invalid_grant" {
		return "", 0, true
	}
	return tok.AccessToken, tok.ExpiresIn, false
}

func postToken(tokenURL string, form url.Values) (googleToken, error) {
	resp, err := httpClient.PostForm(tokenURL, form)
	if err != nil {
		return googleToken{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var t googleToken
	_ = json.Unmarshal(body, &t)
	return t, nil
}

func (h *Handler) userinfoEmail(pc providerConfig, accessToken string) string {
	req, _ := http.NewRequest("GET", pc.userinfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var u struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(body, &u)
	return u.Email
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func bearer(r *http.Request) *auth.Claims {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	c, err := auth.ValidateJWT(strings.TrimPrefix(h, "Bearer "))
	if err != nil {
		return nil
	}
	return c
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
