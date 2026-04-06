package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Env vars required:
//   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
//   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
//   APPLE_CLIENT_ID  (Apple Service ID, e.g. "com.dudenest.web")
//   APP_URL          (e.g. "https://dudenest.com") — where to redirect after auth
//   JWT_SECRET       (already set)

var appURL = func() string {
	u := os.Getenv("APP_URL")
	if u == "" { return "https://dudenest.com" }
	return strings.TrimRight(u, "/")
}()

// RegisterRoutes adds /auth/* handlers to mux
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/google", startGoogle)
	mux.HandleFunc("/auth/github", startGitHub)
	mux.HandleFunc("/auth/apple", startApple)
	mux.HandleFunc("/auth/callback/google", callbackGoogle)
	mux.HandleFunc("/auth/callback/github", callbackGitHub)
}

// ─── State helpers (base64 encodes return_url + provider) ──────────────────

func encodeState(provider, returnURL string) string {
	data, _ := json.Marshal(map[string]string{"p": provider, "r": returnURL})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeState(state string) (provider, returnURL string) {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil { return "", appURL }
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil { return "", appURL }
	return m["p"], m["r"]
}

func callbackRedirect(w http.ResponseWriter, r *http.Request, returnURL string, c Claims) {
	token, err := IssueJWT(c)
	if err != nil { http.Error(w, "jwt error", 500); return }
	userJSON, _ := json.Marshal(map[string]string{
		"id": c.Sub, "email": c.Email, "name": c.Name, "avatar_url": c.Avatar, "provider": c.Provider,
	})
	userB64 := base64.RawURLEncoding.EncodeToString(userJSON)
	if returnURL == "" { returnURL = appURL }
	dest := fmt.Sprintf("%s?token=%s&user=%s", returnURL, url.QueryEscape(token), url.QueryEscape(userB64))
	http.Redirect(w, r, dest, http.StatusFound)
}

// ─── Google ────────────────────────────────────────────────────────────────

func startGoogle(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	if clientID == "" { http.Error(w, "Google OAuth not configured", 503); return }
	returnURL := r.URL.Query().Get("return_url")
	state := encodeState("google", returnURL)
	redirectURI := appURL[:strings.Index(appURL, "//")+2] + "api.dudenest.com/auth/callback/google" // via api subdomain
	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
	}
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+params.Encode(), http.StatusFound)
}

func callbackGoogle(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	_, returnURL := decodeState(state)
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURI := "https://api.dudenest.com/auth/callback/google"
	// Exchange code for tokens
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code": {code}, "client_id": {clientID}, "client_secret": {clientSecret},
		"redirect_uri": {redirectURI}, "grant_type": {"authorization_code"},
	})
	if err != nil { http.Error(w, "token exchange failed", 500); return }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tok struct{ AccessToken string `json:"access_token"` }
	json.Unmarshal(body, &tok)
	// Fetch user info
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	info, err := http.DefaultClient.Do(req)
	if err != nil { http.Error(w, "userinfo failed", 500); return }
	defer info.Body.Close()
	infoBody, _ := io.ReadAll(info.Body)
	var u struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	json.Unmarshal(infoBody, &u)
	log.Printf("Google auth: %s (%s)", u.Email, u.ID)
	callbackRedirect(w, r, returnURL, Claims{Sub: "google:" + u.ID, Email: u.Email, Name: u.Name, Avatar: u.Picture, Provider: "google"})
}

// ─── GitHub ────────────────────────────────────────────────────────────────

func startGitHub(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" { http.Error(w, "GitHub OAuth not configured", 503); return }
	returnURL := r.URL.Query().Get("return_url")
	state := encodeState("github", returnURL)
	params := url.Values{
		"client_id": {clientID}, "scope": {"read:user user:email"}, "state": {state},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

func callbackGitHub(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	_, returnURL := decodeState(state)
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	// Exchange code
	req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", strings.NewReader(url.Values{
		"client_id": {clientID}, "client_secret": {clientSecret}, "code": {code},
	}.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { http.Error(w, "token exchange failed", 500); return }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tok struct{ AccessToken string `json:"access_token"` }
	json.Unmarshal(body, &tok)
	// Fetch user
	uReq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uReq.Header.Set("Accept", "application/vnd.github+json")
	uResp, err := http.DefaultClient.Do(uReq)
	if err != nil { http.Error(w, "user fetch failed", 500); return }
	defer uResp.Body.Close()
	uBody, _ := io.ReadAll(uResp.Body)
	var u struct {
		ID     int64  `json:"id"`
		Login  string `json:"login"`
		Name   string `json:"name"`
		Email  string `json:"email"`
		Avatar string `json:"avatar_url"`
	}
	json.Unmarshal(uBody, &u)
	email := u.Email
	if email == "" { email = fmt.Sprintf("%d+%s@users.noreply.github.com", u.ID, u.Login) }
	log.Printf("GitHub auth: %s (%d)", u.Login, u.ID)
	callbackRedirect(w, r, returnURL, Claims{Sub: fmt.Sprintf("github:%d", u.ID), Email: email, Name: u.Name, Avatar: u.Avatar, Provider: "github"})
}

// ─── Apple ────────────────────────────────────────────────────────────────
// Apple Sign In on web requires a backend with Apple's JWT client_secret.
// For now: redirects to Apple, callback handled via POST (Apple sends form data).
// Full implementation requires: APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY

func startApple(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("APPLE_CLIENT_ID") // Apple Service ID
	if clientID == "" { http.Error(w, "Apple OAuth not configured", 503); return }
	returnURL := r.URL.Query().Get("return_url")
	state := encodeState("apple", returnURL)
	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {"https://api.dudenest.com/auth/callback/apple"},
		"response_type": {"code id_token"},
		"response_mode": {"form_post"},
		"scope":         {"name email"},
		"state":         {state},
	}
	http.Redirect(w, r, "https://appleid.apple.com/auth/authorize?"+params.Encode(), http.StatusFound)
}
