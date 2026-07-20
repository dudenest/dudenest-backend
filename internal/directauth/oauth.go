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

// drive.file (files created by this app) + openid email (verify Drive account == Dudenest account).
const driveScope = "openid email https://www.googleapis.com/auth/drive.file"

// Handler wires the direct-mode Google OAuth endpoints.
type Handler struct {
	Store        Store
	ClientID     string
	ClientSecret string
	RedirectURI  string // https://api.dudenest.com/auth/callback/google/drive
	AppURL       string // https://dudenest.com — open-redirect guard target
	stateSecret  []byte // = JWT_SECRET bytes, HMAC for state integrity
	aead         cipher.AEAD
}

// NewHandler builds a Handler, deriving the AES-GCM cipher from the base64 key (env DRIVE_TOKEN_ENC_KEY).
func NewHandler(store Store, encKeyB64, clientID, clientSecret, redirectURI, appURL, jwtSecret string) (*Handler, error) {
	aead, err := NewCipher(encKeyB64)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Store: store, ClientID: clientID, ClientSecret: clientSecret,
		RedirectURI: redirectURI, AppURL: appURL, stateSecret: []byte(jwtSecret), aead: aead,
	}, nil
}

func (h *Handler) encrypt(pt []byte) ([]byte, error) { return Encrypt(h.aead, pt) }
func (h *Handler) decrypt(ct []byte) ([]byte, error) { return Decrypt(h.aead, ct) }

// ─── State (signed, short-lived): carries user identity + return_url through the redirect ──

type stateData struct {
	Sub   string `json:"s"`
	Email string `json:"e"`
	Ret   string `json:"r"`
	Exp   int64  `json:"x"`
}

func (h *Handler) signState(sub, email, ret string) string {
	raw, _ := json.Marshal(stateData{Sub: sub, Email: email, Ret: ret, Exp: time.Now().Add(10 * time.Minute).Unix()})
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

// safeReturn prevents open redirect: only our own app origins allowed.
func (h *Handler) safeReturn(ret string) string {
	if ret != "" && (strings.HasPrefix(ret, h.AppURL) || strings.HasPrefix(ret, "https://app.dudenest.com")) {
		return ret
	}
	return h.AppURL
}

// ─── Handlers ──────────────────────────────────────────────────────────────

// StartDrive: GET /auth/google/drive?token=<jwt>&return_url=... → redirect to Google consent (offline).
// Auth via query token (a redirect can't carry a Bearer header); identity travels in signed state.
func (h *Handler) StartDrive(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.ValidateJWT(r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.Provider != "google" {
		http.Error(w, "direct mode requires Google login", http.StatusBadRequest)
		return
	}
	ret := h.safeReturn(r.URL.Query().Get("return_url"))
	params := url.Values{
		"client_id":              {h.ClientID},
		"redirect_uri":           {h.RedirectURI},
		"response_type":          {"code"},
		"scope":                  {driveScope},
		"access_type":            {"offline"},   // → refresh token
		"prompt":                 {"consent"},   // force refresh token even on repeat consent
		"include_granted_scopes": {"true"},
		"state":                  {h.signState(claims.Sub, claims.Email, ret)},
	}
	http.Redirect(w, r, googleAuthURL+"?"+params.Encode(), http.StatusFound)
}

// CallbackDrive: GET /auth/callback/google/drive?code=&state= → exchange, verify account, store refresh.
func (h *Handler) CallbackDrive(w http.ResponseWriter, r *http.Request) {
	st, ok := h.verifyState(r.URL.Query().Get("state"))
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	tok, err := h.exchangeCode(r.URL.Query().Get("code"))
	if err != nil || tok.AccessToken == "" {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	email := h.userinfoEmail(tok.AccessToken)
	if email == "" || !strings.EqualFold(email, st.Email) {
		// Isolation: the connected Google account MUST be the Dudenest user's own account.
		http.Error(w, "google account does not match your Dudenest account", http.StatusForbidden)
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
	if err := h.Store.Upsert(r.Context(), st.Sub, sealed, email); err != nil {
		log.Printf("directauth: upsert failed: %v", err)
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	log.Printf("directauth: connected drive for %s (%s)", st.Sub, email)
	sep := "?"
	if strings.Contains(st.Ret, "?") {
		sep = "&"
	}
	http.Redirect(w, r, st.Ret+sep+"drive=connected", http.StatusFound)
}

// Token: GET /api/v1/direct/google/token (Bearer JWT) → fresh drive.file access token (no popup).
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sealed, email, err := h.Store.Get(r.Context(), claims.Sub)
	if err == ErrNotFound {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_connected"})
		return
	} else if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	refresh, err := h.decrypt(sealed)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusInternalServerError)
		return
	}
	access, expiresIn, invalid := h.refreshAccess(string(refresh))
	if invalid {
		_ = h.Store.Delete(r.Context(), claims.Sub) // refresh token revoked → force reconnect
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_connected"})
		return
	}
	if access == "" {
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "expires_in": expiresIn, "email": email})
}

// Disconnect: DELETE /api/v1/direct/google/token → revoke at Google + delete stored token.
func (h *Handler) Disconnect(w http.ResponseWriter, r *http.Request) {
	claims := bearer(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if sealed, _, err := h.Store.Get(r.Context(), claims.Sub); err == nil {
		if refresh, err := h.decrypt(sealed); err == nil {
			_, _ = httpClient.PostForm(googleRevokeURL, url.Values{"token": {string(refresh)}})
		}
	}
	_ = h.Store.Delete(r.Context(), claims.Sub)
	w.WriteHeader(http.StatusNoContent)
}

// ─── Google calls ────────────────────────────────────────────────────────────

type googleToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func (h *Handler) exchangeCode(code string) (googleToken, error) {
	return postToken(url.Values{
		"code": {code}, "client_id": {h.ClientID}, "client_secret": {h.ClientSecret},
		"redirect_uri": {h.RedirectURI}, "grant_type": {"authorization_code"},
	})
}

// refreshAccess returns (accessToken, expiresIn, invalidGrant). invalidGrant=true → token revoked.
func (h *Handler) refreshAccess(refresh string) (string, int, bool) {
	tok, err := postToken(url.Values{
		"client_id": {h.ClientID}, "client_secret": {h.ClientSecret},
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

func postToken(form url.Values) (googleToken, error) {
	resp, err := httpClient.PostForm(googleTokenURL, form)
	if err != nil {
		return googleToken{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var t googleToken
	_ = json.Unmarshal(body, &t)
	return t, nil
}

func (h *Handler) userinfoEmail(accessToken string) string {
	req, _ := http.NewRequest("GET", googleUserinfoURL, nil)
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
