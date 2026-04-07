package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dudenest/dudenest-backend/internal/auth"
	"github.com/dudenest/dudenest-backend/internal/email"
)

var startTime = time.Now()

func main() {
	port := os.Getenv("PORT")
	if port == "" { port = "8080" }
	emailClient, err := email.New()
	if err != nil { log.Printf("warn: email client not available: %v", err) }
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	auth.RegisterRoutes(mux)
	mux.HandleFunc("/api/v1/relay/setup-email", requireAuth(makeRelaySetupEmail(emailClient)))
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
		_, err := auth.ValidateJWT(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		next(w, r)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "uptime": time.Since(startTime).String(), "service": "dudenest-backend",
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

func handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented yet"})
}
