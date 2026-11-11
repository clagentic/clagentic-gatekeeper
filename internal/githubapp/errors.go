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

// TransportError is a failure to reach GitHub or to read its answer: no HTTP
// status was received, or the body could not be read.
type TransportError struct {
	Op   string // what was being done, e.g. "call GitHub API"
	Path string
	Err  error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("%s POST %s: %v", e.Op, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// ResponseError is a 2xx answer from GitHub that gatekeeper could not use: the
// body was not the expected JSON or a field in it did not parse. GitHub did
// answer, so Status and RequestID are known.
type ResponseError struct {
	Op        string // what failed, e.g. "parse response"
	Status    int
	RequestID string // NoRequestID when GitHub sent none
	Err       error
}

func (e *ResponseError) Error() string { return fmt.Sprintf("%s: %v", e.Op, e.Err) }

func (e *ResponseError) Unwrap() error { return e.Err }

// NoRequestID is the placeholder an error carries when GitHub sent no
// X-GitHub-Request-Id.
const NoRequestID = "none"

func requestIDOrNone(id string) string {
	if id == "" {
		return NoRequestID
	}
	return id
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
