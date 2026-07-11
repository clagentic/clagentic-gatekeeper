package attestation_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// TestNewChain_ConfiguredTakesPrecedence verifies the fixed resolution order:
// when the configured provider (layer a) resolves, it wins even though the
// sidecar (layer b) and built-in (layer c) would also resolve.
func TestNewChain_ConfiguredTakesPrecedence(t *testing.T) {
	dir := t.TempDir()

	const configuredVar = "ATTESTATION_TEST_CHAIN_CONFIGURED_LR83549F"
	t.Setenv(configuredVar, "from-configured")

	const sessionEnv = "ATTESTATION_TEST_CHAIN_SESSION_LR83549F"
	t.Setenv(sessionEnv, "session-1")
	sidecarPath := filepath.Join(dir, "sidecar-session-1")
	if err := os.WriteFile(sidecarPath, []byte("from-sidecar"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	resolver, err := attestation.NewChain(attestation.ChainConfig{
		Configured: attestation.ConfiguredConfig{
			Type:   attestation.ConfiguredEnv,
			Source: configuredVar,
		},
		Sidecar: attestation.SidecarConfig{
			Dir:          dir,
			FilePrefix:   "sidecar-",
			SessionIDEnv: sessionEnv,
		},
	})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}

	id, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "from-configured" || id.Source != "configured" {
		t.Errorf("Resolve() = %+v, want Subject=from-configured Source=configured", id)
	}
}

// TestNewChain_SidecarWinsWhenConfiguredAbsent verifies that when layer (a)
// is unconfigured (or declines), layer (b) is used when its file is present.
func TestNewChain_SidecarWinsWhenConfiguredAbsent(t *testing.T) {
	dir := t.TempDir()

	const sessionEnv = "ATTESTATION_TEST_CHAIN_SESSION_LR83549F_2"
	t.Setenv(sessionEnv, "session-2")
	sidecarPath := filepath.Join(dir, "sidecar-session-2")
	if err := os.WriteFile(sidecarPath, []byte("from-sidecar"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	resolver, err := attestation.NewChain(attestation.ChainConfig{
		// Configured left at zero value: layer (a) disabled entirely.
		Sidecar: attestation.SidecarConfig{
			Dir:          dir,
			FilePrefix:   "sidecar-",
			SessionIDEnv: sessionEnv,
		},
	})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}

	id, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "from-sidecar" || id.Source != "sidecar" {
		t.Errorf("Resolve() = %+v, want Subject=from-sidecar Source=sidecar", id)
	}
}

// TestNewChain_BuiltinFallback_BareInstall verifies the headline guarantee:
// a bare install with NO configured provider and NO sidecar still resolves
// an attested identity via the built-in fallback, rather than failing open
// (i.e. Resolve never silently returns a zero-value/empty identity as if it
// were valid — it either returns a real Subject or a definite error).
func TestNewChain_BuiltinFallback_BareInstall(t *testing.T) {
	resolver, err := attestation.NewChain(attestation.ChainConfig{})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}

	id, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error on bare install: %v", err)
	}
	if id.Source != "builtin" {
		t.Errorf("Source = %q, want %q (bare install must fall back to builtin)", id.Source, "builtin")
	}
	if id.Subject == "" {
		t.Error("Subject is empty; bare install must not fail open with an empty attested identity")
	}
}

// TestNewChain_InvalidConfiguredType_FailsClosed verifies a misconfigured
// layer (a) is a hard configuration error at construction time, not a
// silent fall-through to the built-in fallback.
func TestNewChain_InvalidConfiguredType_FailsClosed(t *testing.T) {
	_, err := attestation.NewChain(attestation.ChainConfig{
		Configured: attestation.ConfiguredConfig{Type: "not-a-real-type", Source: "x"},
	})
	if err == nil {
		t.Fatal("NewChain: expected error for invalid configured provider type")
	}
}
