package githubapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const notAccessible = `{"message":"There is at least one repository that does not exist or is not accessible to the parent installation","documentation_url":"https://docs.github.com/rest"}`

// Each row is one fake GitHub answer to the access_tokens call.
func TestExchangeTokenErrorClasses(t *testing.T) {
	for _, c := range []struct {
		name      string
		status    int
		body      string
		requestID string
		wantRepo  bool
		wantIn    []string
	}{
		{"422 repo not accessible", 422, notAccessible, "ABCD:1", true, []string{"REPO_NOT_IN_INSTALLATION", `"example-repo"`, "422", "/app/installations/42/access_tokens", "ABCD:1", "likely cause"}},
		{"422 other message", 422, `{"message":"Validation Failed"}`, "ABCD:2", false, []string{"422", "Validation Failed", "ABCD:2"}},
		{"401", 401, `{"message":"Bad credentials"}`, "", false, []string{"401", "Bad credentials", "request id none"}},
		{"403", 403, `{"message":"Resource not accessible by integration"}`, "R3", false, []string{"403", "R3"}},
		{"404", 404, `{"message":"Not Found"}`, "R4", false, []string{"404", "Not Found"}},
		{"500 empty body", 500, ``, "R5", false, []string{"500", "(empty body)", "/app/installations/42/access_tokens", "R5"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if c.requestID != "" {
					w.Header().Set("X-GitHub-Request-Id", c.requestID)
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			_, err := exchangeToken(context.Background(), srv.URL, 42, "jwt", nil, []string{"example-repo"})
			if err == nil {
				t.Fatal("no error")
			}
			t.Logf("sample: %v", err)
			if got := errors.Is(err, ErrRepoNotInInstallation); got != c.wantRepo {
				t.Fatalf("errors.Is(ErrRepoNotInInstallation) = %v, want %v: %v", got, c.wantRepo, err)
			}
			for _, w := range c.wantIn {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			if strings.Contains(err.Error(), srv.URL) {
				t.Errorf("error %q carries the host", err)
			}
		})
	}
}

func TestExchangeTokenCapsTheBodyExcerpt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(502)
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()

	_, err := exchangeToken(context.Background(), srv.URL, 42, "jwt", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "(truncated)") {
		t.Fatalf("want a truncated excerpt, got %v", err)
	}
	if len(err.Error()) > 1000 {
		t.Fatalf("error is %d bytes, excerpt not capped", len(err.Error()))
	}
}

func TestExchangeTokenTransportErrorNamesThePath(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()

	_, err := exchangeToken(context.Background(), base, 42, "jwt", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "POST /app/installations/42/access_tokens") {
		t.Fatalf("got %v", err)
	}
}
