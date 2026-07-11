package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Demo login: a shared throwaway identity so anyone can try the app without signing in.
// Env-gated (DEMO_ENABLED) and rate-limited so it can't be abused to mint tokens en masse.
//   DEMO_ENABLED=true, DEMO_USER_ID=<uid>, DEMO_USER_EMAIL=demo@dudenest.com
const (
	demoTTL       = 60 * time.Minute // short — a demo session, not a real login
	demoPerIPHour = 20               // per-IP hourly cap
	demoDailyCap  = 500              // global daily cap (bot brake)
)

func demoEnabled() bool {
	switch strings.ToLower(os.Getenv("DEMO_ENABLED")) {
	case "true", "1", "yes":
		return true
	}
	return false
}

type demoLimiter struct {
	mu       sync.Mutex
	perIP    map[string][]time.Time
	dayCount int
	dayStart time.Time
}

var demoLim = &demoLimiter{perIP: map[string][]time.Time{}, dayStart: time.Now()}

// allow reports whether ip may mint a demo token at now, enforcing the per-IP hourly window
// and the global daily cap; both counters roll over after 24h.
func (l *demoLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.dayStart) >= 24*time.Hour {
		l.dayStart, l.dayCount, l.perIP = now, 0, map[string][]time.Time{}
	}
	if l.dayCount >= demoDailyCap {
		return false
	}
	cutoff := now.Add(-time.Hour)
	kept := l.perIP[ip][:0]
	for _, t := range l.perIP[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= demoPerIPHour {
		l.perIP[ip] = kept
		return false
	}
	l.perIP[ip] = append(kept, now)
	l.dayCount++
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// handleDemo mints a short-TTL demo session. 404 when DEMO_ENABLED is off (feature hidden),
// 405 for non-POST, 429 when the rate limit is hit, 503 when not configured.
func handleDemo(w http.ResponseWriter, r *http.Request) {
	if !demoEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !demoLim.allow(clientIP(r), time.Now()) {
		http.Error(w, "demo rate limit — try again later", http.StatusTooManyRequests)
		return
	}
	sub, email := os.Getenv("DEMO_USER_ID"), os.Getenv("DEMO_USER_EMAIL")
	if sub == "" || email == "" {
		http.Error(w, "demo not configured", http.StatusServiceUnavailable)
		return
	}
	token, err := IssueJWTWithTTL(Claims{Sub: sub, Email: email, Name: "Demo", Provider: "demo", Demo: true}, demoTTL)
	if err != nil {
		http.Error(w, "jwt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": token,
		"user":  map[string]any{"id": sub, "email": email, "name": "Demo", "provider": "demo", "demo": true},
	})
}
