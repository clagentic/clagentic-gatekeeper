package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
