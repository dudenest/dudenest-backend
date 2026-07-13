package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq" // CRDB/postgres driver for the HUB-DECOUPLING relays store

	"github.com/dudenest/dudenest-backend/internal/auth"
	"github.com/dudenest/dudenest-backend/internal/email"
	"github.com/dudenest/dudenest-backend/internal/relays"
)

var startTime = time.Now()

// requireEnv aborts startup if any required env var is empty. Prevents the s313 incident pattern:
// a bare `docker stack deploy` with a minimal YAML wiped all Env[] entries and backend kept running
// with empty values, silently returning 503 "Google OAuth not configured" on every login.
// Fail-fast → container crashloop → Swarm rolls back to previous good spec.
func requireEnv(keys ...string) {
	var missing []string
	for _, k := range keys {
		if os.Getenv(k) == "" { missing = append(missing, k) }
	}
	if len(missing) > 0 {
		log.Fatalf("FATAL: required env vars missing: %s — refusing to start with partial config (s313 guard)", strings.Join(missing, ", "))
	}
}

// hubURL returns the dudenest-hub service URL (s334: HUB_URL primary, BACKUP_URL fallback for backward-compat through 1-2 release cycle).
func hubURL() string {
	if u := os.Getenv("HUB_URL"); u != "" { return u }
	return os.Getenv("BACKUP_URL")
}

func main() {
	requireEnv("JWT_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET") // s313 fail-fast: production needs these or login + relay flow is broken
	if hubURL() == "" { log.Fatal("FATAL: HUB_URL (or legacy BACKUP_URL) must be set — refusing to start (s313 guard)") } // s334: dual-name fail-fast
	port := os.Getenv("PORT")
	if port == "" { port = "8080" }
	emailClient, err := email.New()
	if err != nil { log.Printf("warn: email client not available: %v", err) }
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/health/deep", handleHealthDeep) // s337: end-to-end probe — verifies backend → hub proxy chain (catches stale URL config like s337 incident)
	auth.RegisterRoutes(mux)
	mux.HandleFunc("/api/v1/relay/setup-email", requireAuth(makeRelaySetupEmail(emailClient)))
	mux.HandleFunc("/api/v1/relay/install-config", requireAuth(handleRelayInstallConfig))
	mux.HandleFunc("/api/v1/relay/discover", requireAuth(makeHubExactProxy("/user/relay/discover"))) // LAN claim: backend path maps to hub singular /user/relay/discover
	mux.HandleFunc("/api/v1/relays/", requireAuth(makeBackupProxy("/user/relays/"))) // s364: backup subpaths (/{id}/backup) stay on hub proxy for now
	// s364 HUB-DECOUPLING CUTOVER: /api/v1/relays now served directly from CRDB when
	// configured, removing the hub as a SPOF for the relay list (hub down no longer
	// breaks Flutter — root cause of s337/s363). Byte-diff in prod confirmed identical
	// output to the hub proxy incl. relay_token. Falls back to hub proxy if CRDB_DSN
	// unset (e.g. local dev) so the endpoint never hard-fails on missing config.
	if dsn := os.Getenv("CRDB_DSN"); dsn != "" {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			log.Fatalf("FATAL: CRDB_DSN set but sql.Open failed: %v", err)
		}
		mux.HandleFunc("/api/v1/relays", requireAuth(relays.MyRelaysHandler(relays.NewSQLStore(db))))
		log.Printf("s364: /api/v1/relays served from CRDB (hub-decoupled)")
	} else {
		mux.HandleFunc("/api/v1/relays", requireAuth(makeBackupProxy("/user/relays")))
		log.Printf("s364: CRDB_DSN unset — /api/v1/relays falls back to hub proxy")
	}
	mux.HandleFunc("/api/v1/", handleNotImplemented)
	log.Printf("dudenest-backend starting on :%s", port)
	if err := http.ListenAndServe(":"+port, corsMiddleware(mux)); err != nil { log.Fatal(err) }
}

// corsMiddleware allows dudenest.com and app.dudenest.com origins
func corsMiddleware(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"https://dudenest.com":     true,
		"https://app.dudenest.com": true,
		"http://localhost:8787":    true, // local dev
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		next.ServeHTTP(w, r)
	})
}

// requireAuth validates JWT Bearer token — wrap handlers that need auth
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		claims, err := auth.ValidateJWT(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		// s363 HUB-DECOUPLING: expose the JWT `sub` claim to handlers that read
		// relays from CRDB directly. Additive — existing handlers ignore it.
		next(w, r.WithContext(relays.WithUserID(r.Context(), claims.Sub)))
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "uptime": time.Since(startTime).String(), "service": "dudenest-backend",
	})
}

// handleHealthDeep verifies backend → hub proxy chain end-to-end (s337).
// Why: shallow /health returned 200 for 2+ days while backend was misconfigured
// to call dudenest-backup_backup (stale service name post-s334 rename), silently
// breaking /api/v1/relays for all users. This probe catches that class of bug.
// Returns 200 only if hub /health is reachable + responds with status=ok.
// Uptime Kuma should monitor THIS endpoint, not /health.
func handleHealthDeep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hub := hubURL()
	if hub == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"status": "fail", "reason": "HUB_URL not configured"}) //nolint:errcheck
		return
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(hub + "/health")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"status": "fail", "reason": "hub unreachable", "hub_url": hub, "error": err.Error()}) //nolint:errcheck
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"status": "fail", "reason": "hub unhealthy", "hub_status": resp.StatusCode}) //nolint:errcheck
		return
	}
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status": "ok", "uptime": time.Since(startTime).String(), "service": "dudenest-backend",
		"hub_url": hub, "hub_status": "ok",
	})
}

// makeRelaySetupEmail returns handler that sends relay mnemonic email to authenticated user.
// Body: {"email": "...", "name": "...", "mnemonic": "word1 word2 ..."}
// If email/name absent in body, falls back to JWT claims.
func makeRelaySetupEmail(ec *email.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if ec == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "email service unavailable (RESEND_API_KEY not set)"})
			return
		}
		claims, _ := auth.ValidateJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		var body struct {
			Email    string `json:"email"`
			Name     string `json:"name"`
			Mnemonic string `json:"mnemonic"`
		}
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		if body.Email == "" && claims != nil { body.Email = claims.Email }
		if body.Name == "" && claims != nil { body.Name = claims.Name }
		if body.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "email required"})
			return
		}
		if body.Mnemonic == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "mnemonic required"})
			return
		}
		id, err := ec.SendRelayMnemonic(body.Email, body.Name, body.Mnemonic)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "sent", "resend_id": id})
	}
}

// handleRelayInstallConfig returns relay installer configuration for authenticated user.
// Flutter calls this to show the install command in the "Add Relay" screen.
// Returns: jwt_secret, hub_url (s334; backup_url alias for old relays), install_cmd.
// Security: JWT_SECRET exposure is intentional here — only authenticated users reach this
// endpoint, and relay needs the same secret to validate Flutter JWTs.
func handleRelayInstallConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { w.WriteHeader(http.StatusMethodNotAllowed); return }
	jwtSecret := os.Getenv("DUDENEST_JWT_SECRET")
	hub := hubURL()
	if hub == "" { hub = "https://hub.dudenest.com" } // s334: default → new URL
	installCmd := "curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | " +
		"DUDENEST_JWT_SECRET=" + jwtSecret + " HUB_URL=" + hub + " BACKUP_URL=" + hub + " bash" // s334: both vars for backward-compat with old relay binaries (BACKUP_URL alias removed after 30-day grace)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"jwt_secret":  jwtSecret,
		"hub_url":     hub,
		"backup_url":  hub, // s334: alias for backward-compat with old relay binaries; remove after grace period
		"install_cmd": installCmd,
	})
}

func handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented yet"})
}

// makeHubProxy proxies authenticated Flutter requests to dudenest-hub (s334: renamed from makeBackupProxy).
// hubPath is the path prefix on the hub service (e.g. "/user/relays").
// HUB_URL env var must be set (or legacy BACKUP_URL for backward-compat — e.g. "http://dudenest-hub_hub:8087").
func makeBackupProxy(hubPath string) http.HandlerFunc { // s334: function name kept for caller compat; logic uses hubURL()
	hub := hubURL()
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "hub service not configured"}) //nolint:errcheck
			return
		}
		// Build target URL: replace /api/v1/relays prefix with hub path
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/relays")
		target := hub + hubPath + suffix
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil { w.WriteHeader(500); return }
		req.Header.Set("Authorization", r.Header.Get("Authorization")) // forward JWT
		req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("hub proxy error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "hub unavailable"}) //nolint:errcheck
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	}
}

func makeHubExactProxy(hubPath string) http.HandlerFunc {
	hub := hubURL()
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "hub service not configured"}) //nolint:errcheck
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, hub+hubPath, r.Body)
		if err != nil { w.WriteHeader(500); return }
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("hub exact proxy error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "hub unavailable"}) //nolint:errcheck
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	}
}
