package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// openbaobroker satisfies Broker by reading secrets from an OpenBao server.
// AppRole credentials and token are read exclusively from environment variables
// — never from config files or the repo. Secret values are never logged.
type openbaobroker struct {
	endpoint string
	auth     string
}

func newOpenBao(cfg Config) (Broker, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("openbao broker: endpoint is required")
	}
	switch cfg.Auth {
	case "approle", "token":
	default:
		return nil, fmt.Errorf("openbao broker: unknown auth method %q", cfg.Auth)
	}
	return &openbaobroker{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		auth:     cfg.Auth,
	}, nil
}

// clientToken obtains a Vault-compatible client token using the configured auth
// method. The raw token is returned in memory only — it is never logged.
func (b *openbaobroker) clientToken(ctx context.Context) (string, error) {
	switch b.auth {
	case "token":
		tok := os.Getenv("BROKER_TOKEN")
		if tok == "" {
			return "", fmt.Errorf("openbao broker: BROKER_TOKEN is unset or empty")
		}
		return tok, nil

	case "approle":
		roleID := os.Getenv("BROKER_ROLE_ID")
		secretID := os.Getenv("BROKER_SECRET_ID")
		if roleID == "" {
			return "", fmt.Errorf("openbao broker: BROKER_ROLE_ID is unset or empty")
		}
		if secretID == "" {
			return "", fmt.Errorf("openbao broker: BROKER_SECRET_ID is unset or empty")
		}

		body, err := json.Marshal(map[string]string{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return "", fmt.Errorf("openbao broker: marshal approle login: %w", err)
		}

		url := b.endpoint + "/v1/auth/approle/login"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("openbao broker: build approle login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("openbao broker: approle login request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// Discard body to avoid logging any credential material that may
			// appear in error responses from misconfigured servers.
			_, _ = io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("openbao broker: approle login: HTTP %d", resp.StatusCode)
		}

		var result struct {
			Auth struct {
				ClientToken string `json:"client_token"`
			} `json:"auth"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("openbao broker: decode approle login response: %w", err)
		}
		if result.Auth.ClientToken == "" {
			return "", fmt.Errorf("openbao broker: approle login returned empty client_token")
		}
		return result.Auth.ClientToken, nil

	default:
		return "", fmt.Errorf("openbao broker: unknown auth method %q", b.auth)
	}
}

// Get retrieves the secret at the given KV path. It handles both KV v1
// (data.value) and KV v2 (data.data.value) response shapes.
// The returned value is never logged by this package.
func (b *openbaobroker) Get(ctx context.Context, path string) (string, error) {
	tok, err := b.clientToken(ctx)
	if err != nil {
		return "", err
	}

	url := b.endpoint + "/v1/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("openbao broker: build get request for path %q: %w", path, err)
	}
	req.Header.Set("X-Vault-Token", tok)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openbao broker: get request for path %q: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("openbao broker: get path %q: HTTP %d", path, resp.StatusCode)
	}

	// Use a raw-message map so we can distinguish KV v1 vs v2 without
	// unmarshalling potential secret strings into intermediate variables.
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return "", fmt.Errorf("openbao broker: decode response for path %q: %w", path, err)
	}

	// KV v2 wraps the payload in a nested "data" key.
	var v2 struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(envelope.Data, &v2); err == nil && v2.Data.Value != "" {
		return v2.Data.Value, nil
	}

	// Fall back to KV v1 flat structure.
	var v1 struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(envelope.Data, &v1); err != nil {
		return "", fmt.Errorf("openbao broker: parse data for path %q: %w", path, err)
	}
	if v1.Value == "" {
		return "", fmt.Errorf("openbao broker: path %q: data.value is empty", path)
	}
	return v1.Value, nil
}
