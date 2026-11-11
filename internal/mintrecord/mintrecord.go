// Package mintrecord defines the durable per-mint record and the file sink it
// is appended to. A record explains a GitHub App write denial afterwards: it
// names the installation, what was requested, what GitHub granted, and the
// request id GitHub can look the call up by.
//
// A record never carries token material. There is deliberately no field for a
// token, an App private key, a JWT or a broker secret; the only trace of the
// token is Fingerprint, a prefix of its SHA-256 that cannot be reversed.
package mintrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Outcomes of a mint.
const (
	OutcomeOK    = "ok"
	OutcomeError = "error"
)

// Failure categories, stable strings.
const (
	// CategoryRepoNotInInstallation: GitHub refused a requested repository as
	// not covered by the installation.
	CategoryRepoNotInInstallation = "repo_not_in_installation"
	// CategoryGitHubAPI: any other non-2xx answer from GitHub; Status is set.
	CategoryGitHubAPI = "github_api"
	// CategoryGitHubResponse: GitHub answered 2xx but the body could not be
	// parsed (malformed JSON, unparseable expires_at); Status is set.
	CategoryGitHubResponse = "github_response"
	// CategoryTransport: GitHub was not reached or its answer was not read.
	CategoryTransport = "transport"
	// CategoryBroker: a credential could not be read from the broker (App id,
	// installation id, key, slug) or was unusable.
	CategoryBroker = "broker"
	// CategoryEntitlement: attestation or a role refusal, before any GitHub call.
	CategoryEntitlement = "entitlement"
	// CategoryConfig: the request or the deployment configuration cannot mint.
	CategoryConfig = "config"
)

// fingerprintHexLen is how many hex characters of the digest a fingerprint
// keeps: enough to tell two tokens apart, far too few to recover one.
const fingerprintHexLen = 16

// Caller is the attested identity a mint was requested for.
type Caller struct {
	Subject string `json:"subject"`
	Source  string `json:"source"`
	Grade   string `json:"grade,omitempty"`
}

// Record is one mint, written as one JSON object per line.
type Record struct {
	Time                 string            `json:"time"` // RFC 3339, UTC
	Role                 string            `json:"role"`
	Caller               *Caller           `json:"caller,omitempty"`
	AppSlug              string            `json:"app_slug,omitempty"`
	InstallationID       string            `json:"installation_id,omitempty"`
	RequestedRepos       []string          `json:"requested_repositories"`
	RequestedPermissions map[string]string `json:"requested_permissions,omitempty"`
	Outcome              string            `json:"outcome"`
	FailureCategory      string            `json:"failure_category,omitempty"`
	Status               int               `json:"status,omitempty"`
	RequestID            string            `json:"request_id,omitempty"`
	GrantedPermissions   map[string]string `json:"permissions,omitempty"`
	RepositorySelection  string            `json:"repository_selection,omitempty"`
	ExpiresAt            string            `json:"expires_at,omitempty"`
	TokenFingerprint     string            `json:"token_fingerprint,omitempty"`
}

// Fingerprint is the first 16 hex characters of sha256(token). It identifies a
// token in a record without being able to reproduce it.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:fingerprintHexLen]
}

// Sink appends records to a file. The zero value, an empty Path, is off:
// Write does nothing.
type Sink struct {
	Path string
}

// Enabled reports whether the sink writes anything.
func (s Sink) Enabled() bool { return s.Path != "" }

// Write appends r as one line. The file is created 0600 and opened O_APPEND,
// and the line goes out in a single write, so concurrent mints do not
// interleave inside a record. The parent directory must already exist.
func (s Sink) Write(r Record) error {
	if !s.Enabled() {
		return nil
	}
	if r.RequestedRepos == nil {
		r.RequestedRepos = []string{}
	}
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("mint record: encode: %w", err)
	}
	f, err := os.OpenFile(s.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("mint record: open %s: %w", s.Path, err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("mint record: write %s: %w", s.Path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mint record: close %s: %w", s.Path, err)
	}
	return nil
}
