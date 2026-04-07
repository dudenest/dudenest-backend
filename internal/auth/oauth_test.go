package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRoutes_AllEndpointsExist(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	routes := []string{
		"/auth/google",
		"/auth/github",
		"/auth/apple",
		"/auth/callback/google",
		"/auth/callback/github",
	}
	for _, route := range routes {
		req := httptest.NewRequest("GET", route, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Errorf("route %s: got 404 (not registered)", route)
		}
	}
}

func TestEncodeDecodeState_Roundtrip(t *testing.T) {
	cases := []struct{ provider, returnURL string }{
		{"google", "https://dudenest.com"},
		{"github", "https://dudenest.com/app?foo=bar"},
		{"apple", ""},
	}
	for _, c := range cases {
		state := encodeState(c.provider, c.returnURL)
		gotP, gotU := decodeState(state)
		if gotP != c.provider { t.Errorf("provider: got %q want %q", gotP, c.provider) }
		returnURL := c.returnURL
		if returnURL == "" { returnURL = appURL }
		if gotU != returnURL { t.Errorf("returnURL: got %q want %q", gotU, returnURL) }
	}
}

func TestDecodeState_InvalidBase64(t *testing.T) {
	_, url := decodeState("not-valid!!!")
	if url != appURL { t.Errorf("expected fallback to appURL, got %q", url) }
}

func TestDecodeState_InvalidJSON(t *testing.T) {
	_, url := decodeState(b64("{not json}"))
	if url != appURL { t.Errorf("expected fallback to appURL, got %q", url) }
}

func TestStartGoogle_NoClientID(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "") // ensure not configured
	req := httptest.NewRequest("GET", "/auth/google", nil)
	rr := httptest.NewRecorder()
	startGoogle(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when GOOGLE_CLIENT_ID not set, got %d", rr.Code)
	}
}

func TestStartGitHub_NoClientID(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "")
	req := httptest.NewRequest("GET", "/auth/github", nil)
	rr := httptest.NewRecorder()
	startGitHub(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when GITHUB_CLIENT_ID not set, got %d", rr.Code)
	}
}

func TestStartApple_NoClientID(t *testing.T) {
	t.Setenv("APPLE_CLIENT_ID", "")
	req := httptest.NewRequest("GET", "/auth/apple", nil)
	rr := httptest.NewRecorder()
	startApple(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when APPLE_CLIENT_ID not set, got %d", rr.Code)
	}
}

func TestStartGoogle_WithClientID(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	req := httptest.NewRequest("GET", "/auth/google?return_url=https://dudenest.com", nil)
	rr := httptest.NewRecorder()
	startGoogle(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc == "" { t.Error("expected Location header") }
}
