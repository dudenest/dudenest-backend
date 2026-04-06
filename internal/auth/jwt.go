package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

var jwtSecret = []byte(func() string {
	s := os.Getenv("JWT_SECRET")
	if s == "" { return "dev-secret-change-in-prod" }
	return s
}())

type Claims struct {
	Sub      string `json:"sub"`      // user id
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	Provider string `json:"provider"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

func IssueJWT(c Claims) (string, error) {
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(30 * 24 * time.Hour).Unix() // 30 days
	header := b64(`{"alg":"HS256","typ":"JWT"}`)
	payload, err := json.Marshal(c)
	if err != nil { return "", err }
	msg := header + "." + b64(string(payload))
	sig := sign(msg)
	return msg + "." + sig, nil
}

func ValidateJWT(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { return nil, errors.New("invalid token") }
	msg := parts[0] + "." + parts[1]
	if sign(msg) != parts[2] { return nil, errors.New("invalid signature") }
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { return nil, err }
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil { return nil, err }
	if time.Now().Unix() > c.Exp { return nil, errors.New("token expired") }
	return &c, nil
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func sign(msg string) string {
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
