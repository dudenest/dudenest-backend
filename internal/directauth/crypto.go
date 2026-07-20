// Package directauth implements backend-assisted Google Drive OAuth for "direct mode":
// consent via redirect (not a popup), a refresh token stored server-side (encrypted),
// and short-lived drive.file access tokens minted on demand for the Flutter client.
// File bytes still flow Flutter→Drive directly; only auth is backend-assisted.
package directauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// NewCipher builds an AES-256-GCM AEAD from a base64-encoded 32-byte key
// (env DRIVE_TOKEN_ENC_KEY, e.g. `openssl rand -base64 32`).
func NewCipher(b64Key string) (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("DRIVE_TOKEN_ENC_KEY: base64 decode: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("DRIVE_TOKEN_ENC_KEY: need 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt returns nonce||ciphertext (GCM seals + authenticates).
func Encrypt(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt (expects nonce||ciphertext).
func Decrypt(aead cipher.AEAD, blob []byte) ([]byte, error) {
	n := aead.NonceSize()
	if len(blob) < n {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, blob[:n], blob[n:], nil)
}
