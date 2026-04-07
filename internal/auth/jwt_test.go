package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIssueAndValidateJWT_Roundtrip(t *testing.T) {
	c := Claims{Sub: "google:123", Email: "test@example.com", Name: "Test User", Provider: "google"}
	token, err := IssueJWT(c)
	if err != nil { t.Fatal(err) }
	got, err := ValidateJWT(token)
	if err != nil { t.Fatal(err) }
	if got.Sub != c.Sub { t.Errorf("sub: got %q want %q", got.Sub, c.Sub) }
	if got.Email != c.Email { t.Errorf("email: got %q want %q", got.Email, c.Email) }
	if got.Provider != c.Provider { t.Errorf("provider: got %q want %q", got.Provider, c.Provider) }
	if got.Name != c.Name { t.Errorf("name: got %q want %q", got.Name, c.Name) }
}

func TestValidateJWT_InvalidSignature(t *testing.T) {
	c := Claims{Sub: "github:1", Email: "a@b.com", Provider: "github"}
	token, _ := IssueJWT(c)
	parts := strings.SplitN(token, ".", 3)
	tampered := parts[0] + "." + parts[1] + ".invalidsig"
	if _, err := ValidateJWT(tampered); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	cases := []string{"", "only.two", "a.b.c.d"}
	for _, tc := range cases {
		if _, err := ValidateJWT(tc); err == nil {
			t.Errorf("expected error for token %q", tc)
		}
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	c := Claims{Sub: "test", Email: "x@y.com", Provider: "test",
		Exp: time.Now().Add(-1 * time.Second).Unix(),
		Iat: time.Now().Add(-31 * 24 * time.Hour).Unix(),
	}
	header := b64(`{"alg":"HS256","typ":"JWT"}`)
	payload, _ := json.Marshal(c)
	msg := header + "." + b64(string(payload))
	token := msg + "." + sign(msg)
	if _, err := ValidateJWT(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestIssueJWT_SetsTimestamps(t *testing.T) {
	before := time.Now().Unix()
	c := Claims{Sub: "apple:99", Email: "z@z.com", Provider: "apple"}
	token, _ := IssueJWT(c)
	after := time.Now().Unix()
	got, _ := ValidateJWT(token)
	if got.Iat < before || got.Iat > after { t.Errorf("iat %d not in [%d,%d]", got.Iat, before, after) }
	expMin := before + 29*24*3600
	if got.Exp < expMin { t.Errorf("exp %d too small (expected >= %d)", got.Exp, expMin) }
}
