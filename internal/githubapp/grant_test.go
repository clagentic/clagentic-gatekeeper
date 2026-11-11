package githubapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mintAgainst(t *testing.T, apiBase string) (Token, error) {
	t.Helper()
	return Mint(context.Background(), MintRequest{
		APIBase: apiBase, AppID: "12345", InstallationID: "67890",
		PrivateKeyPEM: generateTestPEM(t), TTL: 5 * time.Minute,
	})
}

// A successful exchange keeps what GitHub granted, the status and the request id.
func TestMintKeepsGrantStatusAndRequestID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GitHub-Request-Id", "REQ-OK")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z",` + //nolint:errcheck
			`"permissions":{"contents":"read","metadata":"read"},"repository_selection":"selected"}`))
	}))
	defer srv.Close()

	tok, err := mintAgainst(t, srv.URL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Status != 201 || tok.RequestID != "REQ-OK" || tok.RepositorySelection != "selected" {
		t.Errorf("token = %+v", tok)
	}
	if tok.Permissions["contents"] != "read" || tok.Permissions["metadata"] != "read" || len(tok.Permissions) != 2 {
		t.Errorf("permissions = %v", tok.Permissions)
	}
}

// A response with no request id leaves RequestID empty on success.
func TestMintWithoutRequestIDLeavesItEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	tok, err := mintAgainst(t, srv.URL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.RequestID != "" {
		t.Errorf("RequestID = %q, want empty", tok.RequestID)
	}
}

// An unreachable GitHub is a TransportError, with the message it always had.
func TestMintUnreachableIsTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close()

	_, err := mintAgainst(t, base)
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want a TransportError", err)
	}
	if want := "call GitHub API POST /app/installations/67890/access_tokens: "; len(err.Error()) < len(want) || err.Error()[:len(want)] != want {
		t.Errorf("message = %q, want prefix %q", err.Error(), want)
	}
}
