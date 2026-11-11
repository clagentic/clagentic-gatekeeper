package githubapp

import (
	"errors"
	"fmt"
	"strings"
)

// CodeRepoNotInInstallation is the stable code of ErrRepoNotInInstallation.
const CodeRepoNotInInstallation = "REPO_NOT_IN_INSTALLATION"

// ErrRepoNotInInstallation is the class of a mint whose requested repository
// GitHub says does not exist or is not covered by the installation. Test for it
// with errors.Is.
var ErrRepoNotInInstallation = errors.New(CodeRepoNotInInstallation)

// repoNotInstalledMessage is the fragment of GitHub's documented 422 message
// for a repositories entry the installation cannot reach.
const repoNotInstalledMessage = "does not exist or is not accessible to the parent installation"

// maxBodyExcerpt caps how much of a GitHub error body an error carries.
const maxBodyExcerpt = 512

// RepoNotInInstallationError is the typed form of that 422. It names the
// requested repositories and the request that failed.
type RepoNotInInstallationError struct {
	Repos     []string
	Path      string
	RequestID string
}

func (e *RepoNotInInstallationError) Error() string {
	return fmt.Sprintf("%s: repository %s does not exist or is not covered by the App installation (HTTP 422, POST %s, request id %s); "+
		"the repository name is the likely cause, not the installation: check the spelling and that the App is installed on it",
		CodeRepoNotInInstallation, quoteAll(e.Repos), e.Path, e.RequestID)
}

// Unwrap lets errors.Is match ErrRepoNotInInstallation.
func (e *RepoNotInInstallationError) Unwrap() error { return ErrRepoNotInInstallation }

func quoteAll(names []string) string {
	if len(names) == 0 {
		return "(none named)"
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q, ", ")
}

// APIError is any other non-2xx answer from the access_tokens endpoint.
type APIError struct {
	Status    int
	Path      string
	RequestID string
	Body      string // capped excerpt
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API returned %d for POST %s (request id %s): %s", e.Status, e.Path, e.RequestID, e.Body)
}

// excerpt flattens whitespace and caps a response body.
func excerpt(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > maxBodyExcerpt {
		return s[:maxBodyExcerpt] + "...(truncated)"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
