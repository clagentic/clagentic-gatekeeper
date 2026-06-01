package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMintBadPrivateKey(t *testing.T) {
	_, err := Mint(context.Background(), MintRequest{
		APIBase:        "https://api.github.com",
		AppID:          "12345",
		InstallationID: "67890",
		PrivateKeyPEM:  "this is not a valid PEM key",
		TTL:            5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for garbage PEM, got nil")
	}
	// Key material must not appear in the error.
	if strings.Contains(err.Error(), "this is not a valid PEM key") {
		t.Fatalf("error message leaks private key PEM content: %v", err)
	}
}

func TestMintInvalidAppID(t *testing.T) {
	_, err := Mint(context.Background(), MintRequest{
		APIBase:        "https://api.github.com",
		AppID:          "not-a-number",
		InstallationID: "67890",
		PrivateKeyPEM:  generateTestPEM(t),
		TTL:            5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for non-numeric AppID, got nil")
	}
}

func TestMintHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Authorization header.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing Bearer token", http.StatusUnauthorized)
			return
		}
		// Validate JWT structure: three dot-separated segments.
		token := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			http.Error(w, "JWT must have 3 segments", http.StatusUnauthorized)
			return
		}
		for _, part := range parts {
			if part == "" {
				http.Error(w, "JWT segment must not be empty", http.StatusUnauthorized)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_test",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	tok, err := Mint(context.Background(), MintRequest{
		APIBase:        srv.URL,
		AppID:          "12345",
		InstallationID: "67890",
		PrivateKeyPEM:  generateTestPEM(t),
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Value != "ghs_test" {
		t.Fatalf("expected token value %q, got %q", "ghs_test", tok.Value)
	}
	if tok.ExpiresAt.Year() != 2099 {
		t.Fatalf("expected expiry year 2099, got %d", tok.ExpiresAt.Year())
	}
}

// generateTestPEM generates a fresh RSA-2048 private key and returns it as a
// PKCS#1 PEM string. Fails the test immediately on any error.
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}
