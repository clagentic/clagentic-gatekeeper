package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

func TestNewSidecarProvider_UnconfiguredReturnsNil(t *testing.T) {
	cases := []struct {
		name string
		cfg  attestation.SidecarConfig
	}{
		{"all empty", attestation.SidecarConfig{}},
		{"missing dir", attestation.SidecarConfig{FilePrefix: "p-", SessionIDEnv: "X"}},
		{"missing prefix", attestation.SidecarConfig{Dir: "/tmp", SessionIDEnv: "X"}},
		{"missing session env", attestation.SidecarConfig{Dir: "/tmp", FilePrefix: "p-"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p, err := attestation.NewSidecarProvider(tc.cfg)
			if err != nil {
				t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
			}
			if p != nil {
				t.Errorf("NewSidecarProvider(%+v) = %v, want nil provider (adapter must not be assumed)", tc.cfg, p)
			}
		})
	}
}

func TestSidecarProvider_NoSessionID_Declines(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_SIDECAR_SESSION_LR83549F"
	os.Unsetenv(sessionEnv)

	dir := t.TempDir()
	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   "identity-",
		SessionIDEnv: sessionEnv,
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}

	_, err = p.Resolve(context.Background())
	if !errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}

func TestSidecarProvider_FileAbsent_Declines(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_SIDECAR_SESSION_LR83549F_2"
	dir := t.TempDir()

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   "identity-",
		SessionIDEnv: sessionEnv,
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}

	t.Setenv(sessionEnv, "session-123")

	// The sidecar file for this session was never written — adapter must
	// decline rather than assume the sidecar harness is present.
	_, err = p.Resolve(context.Background())
	if !errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}

func TestSidecarProvider_FilePresent_Resolves(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_SIDECAR_SESSION_LR83549F_3"
	dir := t.TempDir()
	const prefix = "identity-"
	const sessionID = "session-abc"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   prefix,
		SessionIDEnv: sessionEnv,
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}

	t.Setenv(sessionEnv, sessionID)

	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte("agent-z\n"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "agent-z" {
		t.Errorf("Subject = %q, want %q", id.Subject, "agent-z")
	}
	if id.Source != "sidecar" {
		t.Errorf("Source = %q, want %q", id.Source, "sidecar")
	}
}

// TestSidecarProvider_UnsafeSessionID_Declines verifies that a sessionID
// containing path separators, "..", or an absolute path is rejected before
// any file is read — a session ID is an opaque token from the environment,
// never a path, and must not be able to redirect the read outside cfg.Dir
// (bobbie.sast.5, path traversal).
func TestSidecarProvider_UnsafeSessionID_Declines(t *testing.T) {
	cases := []struct {
		name      string
		sessionID string
	}{
		{"parent traversal", "../../etc/passwd"},
		{"single parent segment", ".."},
		{"embedded separator", "foo/bar"},
		{"embedded backslash", `foo\bar`},
		{"absolute path", "/etc/passwd"},
		{"current dir", "."},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sessionEnv := "ATTESTATION_TEST_SIDECAR_UNSAFE_" + sanitizeEnvSuffix(tc.name)
			dir := t.TempDir()

			// Plant a file outside dir that a successful traversal would read,
			// so the test would fail loudly (wrong Subject) instead of just
			// timing out if containment ever regresses.
			outsideDir := t.TempDir()
			secretPath := filepath.Join(outsideDir, "passwd")
			if err := os.WriteFile(secretPath, []byte("root:x:0:0"), 0o600); err != nil {
				t.Fatalf("setup: write outside file: %v", err)
			}

			p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
				Dir:          dir,
				FilePrefix:   "identity-",
				SessionIDEnv: sessionEnv,
			})
			if err != nil {
				t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
			}

			t.Setenv(sessionEnv, tc.sessionID)

			id, err := p.Resolve(context.Background())
			if err == nil {
				t.Fatalf("Resolve() = %+v, nil; want an error for unsafe sessionID %q", id, tc.sessionID)
			}
			if id.Subject == "root:x:0:0" {
				t.Fatal("Resolve() returned contents of a file outside cfg.Dir; traversal succeeded")
			}
		})
	}
}

// TestSidecarProvider_SymlinkInDir_Refuses verifies that when the resolved
// sidecar filename is a symlink (e.g. planted in a world-writable dir like
// /tmp), Resolve refuses to follow it rather than returning the linked
// file's contents as the trusted Identity.Subject (bobbie.sast.5).
func TestSidecarProvider_SymlinkInDir_Refuses(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_SIDECAR_SYMLINK_LR83549F"
	dir := t.TempDir()
	const prefix = "identity-"
	const sessionID = "session-symlink"

	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(secretPath, []byte("attacker-controlled-identity"), 0o600); err != nil {
		t.Fatalf("setup: write outside file: %v", err)
	}

	linkPath := filepath.Join(dir, prefix+sessionID)
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Fatalf("setup: create symlink: %v", err)
	}

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   prefix,
		SessionIDEnv: sessionEnv,
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}

	t.Setenv(sessionEnv, sessionID)

	id, err := p.Resolve(context.Background())
	if err == nil {
		t.Fatalf("Resolve() = %+v, nil; want a refusal for a symlinked identity file", id)
	}
	if id.Subject == "attacker-controlled-identity" {
		t.Fatal("Resolve() followed the symlink and returned the linked file's contents")
	}
}

// sanitizeEnvSuffix converts a test-case name into a string safe to append
// to an environment variable name (letters/digits/underscore only).
func sanitizeEnvSuffix(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func TestSidecarProvider_EmptyFile_Declines(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_SIDECAR_SESSION_LR83549F_4"
	dir := t.TempDir()
	const prefix = "identity-"
	const sessionID = "session-empty"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   prefix,
		SessionIDEnv: sessionEnv,
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}

	t.Setenv(sessionEnv, sessionID)

	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	_, err = p.Resolve(context.Background())
	if !errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}
