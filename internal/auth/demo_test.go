package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func resetDemoLimiter() {
	demoLim = &demoLimiter{perIP: map[string][]time.Time{}, dayStart: time.Now()}
}

func postDemo(t *testing.T, ip string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/auth/demo", nil)
	r.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()
	handleDemo(w, r)
	return w
}

func TestDemoDisabledReturns404(t *testing.T) {
	t.Setenv("DEMO_ENABLED", "")
	if got := postDemo(t, "1.1.1.1").Code; got != http.StatusNotFound {
		t.Fatalf("disabled → %d, want 404", got)
	}
}

func TestDemoGetNotAllowed(t *testing.T) {
	t.Setenv("DEMO_ENABLED", "true")
	t.Setenv("DEMO_USER_ID", "demo-uid")
	t.Setenv("DEMO_USER_EMAIL", "demo@dudenest.com")
	resetDemoLimiter()
	r := httptest.NewRequest(http.MethodGet, "/auth/demo", nil)
	w := httptest.NewRecorder()
	handleDemo(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET → %d, want 405", w.Code)
	}
}

func TestDemoIssuesShortLivedDemoToken(t *testing.T) {
	t.Setenv("DEMO_ENABLED", "1")
	t.Setenv("DEMO_USER_ID", "demo-uid")
	t.Setenv("DEMO_USER_EMAIL", "demo@dudenest.com")
	resetDemoLimiter()
	w := postDemo(t, "2.2.2.2")
	if w.Code != http.StatusOK {
		t.Fatalf("POST → %d, want 200", w.Code)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("no token in response: %v %s", err, w.Body)
	}
	c, err := ValidateJWT(body.Token)
	if err != nil {
		t.Fatalf("token invalid: %v", err)
	}
	if !c.Demo || c.Sub != "demo-uid" || c.Email != "demo@dudenest.com" {
		t.Fatalf("claims wrong: %+v", c)
	}
	if ttl := time.Until(time.Unix(c.Exp, 0)); ttl > demoTTL+time.Minute || ttl < demoTTL-2*time.Minute {
		t.Fatalf("TTL %v, want ~%v", ttl, demoTTL)
	}
}

func TestDemoNotConfiguredReturns503(t *testing.T) {
	t.Setenv("DEMO_ENABLED", "true")
	t.Setenv("DEMO_USER_ID", "")
	t.Setenv("DEMO_USER_EMAIL", "")
	resetDemoLimiter()
	if got := postDemo(t, "3.3.3.3").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("misconfigured → %d, want 503", got)
	}
}

func TestDemoPerIPRateLimit(t *testing.T) {
	t.Setenv("DEMO_ENABLED", "true")
	t.Setenv("DEMO_USER_ID", "demo-uid")
	t.Setenv("DEMO_USER_EMAIL", "demo@dudenest.com")
	resetDemoLimiter()
	for i := 0; i < demoPerIPHour; i++ {
		if got := postDemo(t, "4.4.4.4").Code; got != http.StatusOK {
			t.Fatalf("req %d → %d, want 200", i, got)
		}
	}
	if got := postDemo(t, "4.4.4.4").Code; got != http.StatusTooManyRequests {
		t.Fatalf("over limit → %d, want 429", got)
	}
	// a different IP is unaffected
	if got := postDemo(t, "5.5.5.5").Code; got != http.StatusOK {
		t.Fatalf("other IP → %d, want 200", got)
	}
}
