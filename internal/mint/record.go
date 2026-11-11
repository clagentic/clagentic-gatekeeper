package mint

import (
	"errors"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/mintrecord"
)

// trace is what a mint learns on the way, kept so a refusal part-way through
// still yields a record that says how far it got.
type trace struct {
	identity       *attestation.Identity
	appSlug        string
	installationID string
	permissions    map[string]string
}

// categorizedError tags an error with its failure category without changing
// its text or hiding the error it wraps.
type categorizedError struct {
	category string
	err      error
}

func (e *categorizedError) Error() string { return e.err.Error() }
func (e *categorizedError) Unwrap() error { return e.err }

func categorize(category string, err error) error {
	return &categorizedError{category: category, err: err}
}

// failure derives the record's category, HTTP status and request id from err.
// An error from GitHub carries its own status and request id; an error that
// reaches here with no tag and no GitHub type came from the credentials the
// broker handed to githubapp (an unusable id or key), so it is a broker failure.
func failure(err error) (category string, status int, requestID string) {
	var repoErr *githubapp.RepoNotInInstallationError
	var apiErr *githubapp.APIError
	var transportErr *githubapp.TransportError
	var responseErr *githubapp.ResponseError
	var tagged *categorizedError
	switch {
	case errors.As(err, &responseErr):
		return mintrecord.CategoryGitHubResponse, responseErr.Status, requestIDOrEmpty(responseErr.RequestID)
	case errors.As(err, &repoErr):
		return mintrecord.CategoryRepoNotInInstallation, 422, requestIDOrEmpty(repoErr.RequestID)
	case errors.As(err, &apiErr):
		return mintrecord.CategoryGitHubAPI, apiErr.Status, requestIDOrEmpty(apiErr.RequestID)
	case errors.As(err, &transportErr):
		return mintrecord.CategoryTransport, 0, ""
	case errors.As(err, &tagged):
		return tagged.category, 0, ""
	}
	return mintrecord.CategoryBroker, 0, ""
}

func requestIDOrEmpty(id string) string {
	if id == githubapp.NoRequestID {
		return ""
	}
	return id
}

// buildRecord assembles the record for one finished mint. It reads the token
// only to fingerprint it.
func (s *Service) buildRecord(roleName string, repos []string, tr *trace, token githubapp.Token, err error) mintrecord.Record {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	rec := mintrecord.Record{
		Time:                 now().UTC().Format(time.RFC3339),
		Role:                 roleName,
		AppSlug:              tr.appSlug,
		InstallationID:       tr.installationID,
		RequestedRepos:       repos,
		RequestedPermissions: tr.permissions,
	}
	if tr.identity != nil {
		rec.Caller = &mintrecord.Caller{Subject: tr.identity.Subject, Source: tr.identity.Source, Grade: tr.identity.Grade}
	}
	if err != nil {
		rec.Outcome = mintrecord.OutcomeError
		rec.FailureCategory, rec.Status, rec.RequestID = failure(err)
		return rec
	}
	rec.Outcome = mintrecord.OutcomeOK
	rec.Status = token.Status
	rec.RequestID = token.RequestID
	rec.GrantedPermissions = token.Permissions
	rec.RepositorySelection = token.RepositorySelection
	if !token.ExpiresAt.IsZero() {
		rec.ExpiresAt = token.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if token.Value != "" {
		rec.TokenFingerprint = mintrecord.Fingerprint(token.Value)
	}
	return rec
}
