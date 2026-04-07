// Package email sends transactional emails via Resend.com REST API.
// Requires env: RESEND_API_KEY
// From address: app@dudenest.com (must be verified domain in Resend dashboard)
package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	resendURL  = "https://api.resend.com/emails"
	fromAddr   = "Dudenest <app@dudenest.com>"
	httpTimeout = 10 * time.Second
)

// Client sends emails via Resend.com.
type Client struct {
	apiKey string
	http   *http.Client
}

// New creates an email client from RESEND_API_KEY env var.
func New() (*Client, error) {
	key := os.Getenv("RESEND_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("RESEND_API_KEY not set")
	}
	return &Client{apiKey: key, http: &http.Client{Timeout: httpTimeout}}, nil
}

type sendReq struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Html    string   `json:"html"`
	Text    string   `json:"text"`
}

type sendResp struct {
	ID    string `json:"id"`
	Error string `json:"message,omitempty"`
}

// Send sends a single email. Returns Resend email ID on success.
func (c *Client) Send(to, subject, html, text string) (string, error) {
	body, _ := json.Marshal(sendReq{From: fromAddr, To: []string{to}, Subject: subject, Html: html, Text: text})
	req, err := http.NewRequest(http.MethodPost, resendURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("resend request: %w", err)
	}
	defer resp.Body.Close()
	var r sendResp
	json.NewDecoder(resp.Body).Decode(&r) //nolint:errcheck
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("resend HTTP %d: %s", resp.StatusCode, r.Error)
	}
	return r.ID, nil
}

// SendRelayMnemonic sends the BIP39 recovery mnemonic to the user's email.
func (c *Client) SendRelayMnemonic(toEmail, userName, mnemonic string) (string, error) {
	words := strings.Fields(mnemonic)
	wordsHTML := ""
	for i, w := range words {
		wordsHTML += fmt.Sprintf(`<span style="display:inline-block;margin:4px 8px;padding:6px 12px;background:#1a2744;border:1px solid #3a5784;border-radius:6px;font-family:monospace;font-size:16px;color:#aaccff"><b>%d.</b> %s</span>`, i+1, w)
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="background:#060c1a;color:#cce;font-family:sans-serif;padding:40px 20px;max-width:600px;margin:0 auto">
<h1 style="color:#4488ff;font-size:24px">🔑 Your Dudenest Recovery Mnemonic</h1>
<p>Hi %s,</p>
<p>Your Dudenest Relay has been set up. Below is your <strong>12-word recovery mnemonic</strong>.</p>
<div style="background:#0d1b3e;border:2px solid #2a4a7a;border-radius:12px;padding:24px;margin:24px 0">
  <p style="color:#ff4444;font-weight:bold;margin:0 0 16px">⚠️ WRITE THESE WORDS DOWN. Store them safely offline.</p>
  <div>%s</div>
</div>
<p><strong>What is this?</strong> If you ever lose access to your relay or need to restore it on a new device, these 12 words will recover all your encrypted files.</p>
<p>Without this mnemonic, your files CANNOT be recovered — not by you, not by us.</p>
<hr style="border-color:#1a3060;margin:32px 0">
<p style="color:#4a6080;font-size:12px">To recover: <code style="color:#88aacc">relay recover --mnemonic "word1 word2 ..."</code></p>
<p style="color:#4a6080;font-size:12px">Dudenest — Your files. Your cloud. · <a href="https://dudenest.com" style="color:#4488ff">dudenest.com</a></p>
</body></html>`, userName, wordsHTML)
	text := fmt.Sprintf("Your Dudenest Recovery Mnemonic\n\nHi %s,\n\nYour relay recovery mnemonic (WRITE THESE DOWN):\n\n%s\n\nWithout this mnemonic, your files cannot be recovered.\n\nTo recover: relay recover --mnemonic \"...\"\n\nDudenest — dudenest.com", userName, mnemonic)
	return c.Send(toEmail, "🔑 Your Dudenest Recovery Mnemonic — Save This Now", html, text)
}
