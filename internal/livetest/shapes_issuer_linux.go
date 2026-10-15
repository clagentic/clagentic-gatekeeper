//go:build linux

package livetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// shape is one named caller shape. A nil error is a pass; skipError is a skip.
type shape struct {
	name string
	run  func(ctx context.Context) error
}

type skipError struct{ reason string }

func (s skipError) Error() string { return s.reason }

func skipf(format string, args ...any) error { return skipError{fmt.Sprintf(format, args...)} }

// wrapped runs the binary the way a runtime that starts hooks through a command
// string does. The trailing echo keeps the shell from replacing itself with the
// command, so the wrapper really is the parent; the saved status is returned so
// the echo never masks the wrapped command's own exit status.
const wrapperScript = `"$0" "$@"; status=$?; echo wrapped >&2; exit $status`

func (e *Env) wrapped(ctx context.Context, args ...string) (procResult, error) {
	return e.wrappedIn(ctx, "", args...)
}

// wrappedIn is wrapped with a payload on the command's standard input.
func (e *Env) wrappedIn(ctx context.Context, stdin string, args ...string) (procResult, error) {
	sh, err := lookShell()
	if err != nil {
		return procResult{}, err
	}
	return e.gkIn2(ctx, stdin, sh, append([]string{"-c", wrapperScript, e.Bin}, args...)...)
}

// gk2 runs an arbitrary program with the minimal environment and a bounded life.
func (e *Env) gk2(ctx context.Context, name string, args ...string) (procResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return e.run(ctx, runOpts{}, name, args...)
}

func lookShell() (string, error) {
	p, err := exec.LookPath("sh")
	if err != nil {
		return "", skipf("no POSIX shell on PATH to act as a command wrapper")
	}
	return p, nil
}

func parseIssued(stdout string) (*identity.Issued, error) {
	var out identity.Issued
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return nil, fmt.Errorf("the command did not print the issued JSON: %w", err)
	}
	return &out, nil
}

// checkIssued verifies an issuance end to end: the token against the published
// keys, the claims against what was asked for, and the delivery directory.
func (e *Env) checkIssued(out *identity.Issued, roles []string, grade string) (Claims, error) {
	c, err := e.verify(out.Token)
	if err != nil {
		return c, fmt.Errorf("the assertion does not verify: %w", err)
	}
	if c.Grade != grade {
		return c, fmt.Errorf("grade %q, want %q", c.Grade, grade)
	}
	if !sameSet(c.Roles, roles) || !sameSet(out.Roles, roles) {
		return c, fmt.Errorf("roles %v (response %v), want %v", c.Roles, out.Roles, roles)
	}
	if !strings.HasPrefix(out.Dir, e.Spawn+string(filepath.Separator)) {
		return c, errors.New("the delivery directory is not under the spawn root")
	}
	raw, err := os.ReadFile(filepath.Join(out.Dir, identity.DeliveryFile))
	if err != nil || strings.TrimSpace(string(raw)) != out.Token {
		return c, fmt.Errorf("the delivered file does not hold the issued token (%v)", err)
	}
	return c, nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// runtimeID is what the issuer must report as rt.id for a session owned by this
// process: the executable of the runtime process, which for a client of the
// socket is this one, never the short-lived client or its command wrapper.
func runtimeID() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Base(exe), nil
}

func (e *Env) issuerShapes() []shape {
	return []shape{
		{"issuer/session-direct-client", e.shapeSessionDirect},
		{"issuer/assertion-verifies-against-published-keys", e.shapeVerifyJWKS},
		{"issuer/session-cli-direct", e.shapeSessionCLI(false)},
		{"issuer/session-cli-under-command-wrapper", e.shapeSessionCLI(true)},
		{"issuer/child-under-command-wrapper-same-runtime", e.shapeChildSameRuntime},
		{"issuer/child-under-different-runtime-refused", e.shapeChildOtherRuntime},
		{"issuer/unknown-definition-refused", e.shapeUnknownDefinition},
		{"adapter-process/child-holds-assertion", e.shapeProcessAdapter},
	}
}

func (e *Env) shapeSessionDirect(ctx context.Context) error {
	out, err := e.client().IssueSession(identity.SessionRequest{Definition: defLead})
	if err != nil {
		return err
	}
	c, err := e.checkIssued(out, []string{"builder", "reviewer"}, "workload")
	if err != nil {
		return err
	}
	want, err := runtimeID()
	if err != nil {
		return err
	}
	if c.RT.ID != want {
		return fmt.Errorf("rt.id %q, want the direct client's own executable %q", c.RT.ID, want)
	}
	return nil
}

func (e *Env) shapeVerifyJWKS(ctx context.Context) error {
	out, err := e.client().IssueSession(identity.SessionRequest{Definition: defBuilder})
	if err != nil {
		return err
	}
	file, err := e.publishedKeys()
	if err != nil {
		return err
	}
	served, err := e.client().FetchJWKS()
	if err != nil {
		return fmt.Errorf("the socket does not serve the key set: %w", err)
	}
	if mustJSON(file) != mustJSON(served) {
		return errors.New("the key set on the socket differs from the published file")
	}
	for name, set := range map[string]identity.JWKS{"file": file, "socket": served} {
		if _, err := VerifyAssertion(out.Token, set, time.Now()); err != nil {
			return fmt.Errorf("verification against the %s key set: %w", name, err)
		}
	}
	// A relying party must refuse a changed payload and a key it does not know.
	parts := strings.Split(out.Token, ".")
	tampered := parts[0] + "." + flipFirst(parts[1]) + "." + parts[2]
	if _, err := VerifyAssertion(tampered, file, time.Now()); err == nil {
		return errors.New("an assertion with a changed payload verified")
	}
	if _, err := VerifyAssertion(out.Token, identity.JWKS{}, time.Now()); err == nil {
		return errors.New("an assertion verified against an empty key set")
	}
	return nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (e *Env) shapeSessionCLI(viaWrapper bool) func(context.Context) error {
	return func(ctx context.Context) error {
		args := []string{"issue-session", "--socket", e.Sock, "--definition", defLead, "--json"}
		var res procResult
		var err error
		if viaWrapper {
			res, err = e.wrapped(ctx, args...)
		} else {
			res, err = e.gk(ctx, runOpts{}, args...)
		}
		if err != nil {
			return err
		}
		if res.Code != 0 {
			return fmt.Errorf("exit %d: %.300s", res.Code, res.Stderr)
		}
		out, err := parseIssued(res.Stdout)
		if err != nil {
			return err
		}
		c, err := e.checkIssued(out, []string{"builder", "reviewer"}, "workload")
		if err != nil {
			return err
		}
		// Bound to the runtime above the client, not to the client or its wrapper.
		want, err := runtimeID()
		if err != nil {
			return err
		}
		if c.RT.ID != want {
			return fmt.Errorf("rt.id %q, want the owning runtime %q", c.RT.ID, want)
		}
		return nil
	}
}

func (e *Env) childArgs(parent *identity.Issued, id string) []string {
	return []string{"issue-child", "--socket", e.Sock, "--parent-token-file", filepath.Join(parent.Dir, identity.DeliveryFile),
		"--agent-type", defBuilder, "--agent-id", id, "--json"}
}

func (e *Env) shapeChildSameRuntime(ctx context.Context) error {
	parent, err := e.client().IssueSession(identity.SessionRequest{Definition: defLead})
	if err != nil {
		return err
	}
	pc, err := e.verify(parent.Token)
	if err != nil {
		return err
	}
	res, err := e.wrapped(ctx, e.childArgs(parent, "live-child-1")...)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("exit %d: %.300s", res.Code, res.Stderr)
	}
	out, err := parseIssued(res.Stdout)
	if err != nil {
		return err
	}
	c, err := e.checkIssued(out, []string{"builder"}, "harness")
	if err != nil {
		return err
	}
	if c.Spawn != "live-child-1" || c.Sid != pc.Sid || c.Act == nil || c.Act.Sub != "agent:"+defBuilder {
		return fmt.Errorf("child claims spawn=%q sid-matches-parent=%v act=%v", c.Spawn, c.Sid == pc.Sid, c.Act)
	}
	return nil
}

func (e *Env) shapeChildOtherRuntime(ctx context.Context) error {
	sh, err := lookShell()
	if err != nil {
		return err
	}
	parent, err := e.client().IssueSession(identity.SessionRequest{Definition: defLead})
	if err != nil {
		return err
	}
	// A shell running a script file is a runtime of its own, never a wrapper, so
	// the client below it belongs to a different runtime than the parent's.
	launcher := filepath.Join(e.Dir, "launcher.sh")
	if err := os.WriteFile(launcher, []byte("\"$@\"\nstatus=$?\necho launched >&2\nexit $status\n"), 0o600); err != nil {
		return err
	}
	res, err := e.gk2(ctx, sh, append([]string{launcher, e.Bin}, e.childArgs(parent, "live-child-2")...)...)
	if err != nil {
		return err
	}
	if res.Code == 0 || res.Stdout != "" {
		return fmt.Errorf("a client under another runtime was served (exit %d, stdout %.100q)", res.Code, res.Stdout)
	}
	if !strings.Contains(res.Stderr, identity.CodePIDMismatch) {
		return fmt.Errorf("refused, but not as %s: %.300s", identity.CodePIDMismatch, res.Stderr)
	}
	return nil
}

func (e *Env) shapeUnknownDefinition(ctx context.Context) error {
	_, err := e.client().IssueSession(identity.SessionRequest{Definition: "no-such-definition"})
	ie, ok := identity.IsIssueError(err)
	if !ok || ie.Code != identity.CodeDefinitionUnknown {
		return fmt.Errorf("want %s, got %v", identity.CodeDefinitionUnknown, err)
	}
	return nil
}

// shapeProcessAdapter plays the launcher: it takes the assignment the adapter
// prints, puts it in a child's environment and checks the child holds a valid
// assertion without doing anything per command.
func (e *Env) shapeProcessAdapter(ctx context.Context) error {
	sh, err := lookShell()
	if err != nil {
		return err
	}
	res, err := e.gk(ctx, runOpts{}, "hook", "process", "--socket", e.Sock, "--definition", defBuilder)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("exit %d: %.300s", res.Code, res.Stderr)
	}
	assignment := strings.TrimSpace(res.Stdout)
	if !strings.HasPrefix(assignment, "CLAGENTIC_IDENTITY_DIR=") || strings.Count(assignment, "\n") != 0 {
		return fmt.Errorf("unexpected assignment %q", assignment)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	child, err := e.run(ctx, runOpts{Env: []string{assignment}}, sh, "-c", `cat "$CLAGENTIC_IDENTITY_DIR/identity.jwt"`)
	if err != nil {
		return err
	}
	if child.Code != 0 {
		return fmt.Errorf("the child could not read its assertion: %.300s", child.Stderr)
	}
	c, err := e.verify(child.Stdout)
	if err != nil {
		return fmt.Errorf("the child's assertion does not verify: %w", err)
	}
	if c.Grade != "workload" || !sameSet(c.Roles, []string{"builder"}) || c.Act == nil || c.Act.Sub != "agent:"+defBuilder {
		return fmt.Errorf("child claims grade=%q roles=%v act=%v", c.Grade, c.Roles, c.Act)
	}
	return nil
}
