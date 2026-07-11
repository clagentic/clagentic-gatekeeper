package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

func TestNewConfiguredProvider_None(t *testing.T) {
	p, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{Type: attestation.ConfiguredNone})
	if err != nil {
		t.Fatalf("NewConfiguredProvider(none): unexpected error: %v", err)
	}
	if p != nil {
		t.Errorf("NewConfiguredProvider(none) = %v, want nil provider", p)
	}
}

func TestNewConfiguredProvider_UnknownType(t *testing.T) {
	_, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{Type: "notatype", Source: "x"})
	if err == nil {
		t.Fatal("expected error for unknown configured provider type")
	}
}

func TestNewConfiguredProvider_MissingSource(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		_, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{Type: attestation.ConfiguredEnv})
		if err == nil {
			t.Fatal("expected error for env type without source")
		}
	})
	t.Run("file", func(t *testing.T) {
		_, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{Type: attestation.ConfiguredFile})
		if err == nil {
			t.Fatal("expected error for file type without source")
		}
	})
}

func TestConfiguredProvider_Env(t *testing.T) {
	const varName = "ATTESTATION_TEST_ENV_VAR_LR83549F"
	os.Unsetenv(varName)

	p, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{
		Type:   attestation.ConfiguredEnv,
		Source: varName,
	})
	if err != nil {
		t.Fatalf("NewConfiguredProvider(env): unexpected error: %v", err)
	}

	t.Run("unset variable declines", func(t *testing.T) {
		_, err := p.Resolve(context.Background())
		if !errors.Is(err, attestation.ErrNoIdentity) {
			t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
		}
	})

	t.Run("set variable resolves", func(t *testing.T) {
		t.Setenv(varName, "  agent-x  ")
		id, err := p.Resolve(context.Background())
		if err != nil {
			t.Fatalf("Resolve(): unexpected error: %v", err)
		}
		if id.Subject != "agent-x" {
			t.Errorf("Subject = %q, want %q", id.Subject, "agent-x")
		}
		if id.Source != "configured" {
			t.Errorf("Source = %q, want %q", id.Source, "configured")
		}
	})

	t.Run("empty variable declines", func(t *testing.T) {
		t.Setenv(varName, "   ")
		_, err := p.Resolve(context.Background())
		if !errors.Is(err, attestation.ErrNoIdentity) {
			t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
		}
	})
}

func TestConfiguredProvider_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")

	p, err := attestation.NewConfiguredProvider(attestation.ConfiguredConfig{
		Type:   attestation.ConfiguredFile,
		Source: path,
	})
	if err != nil {
		t.Fatalf("NewConfiguredProvider(file): unexpected error: %v", err)
	}

	t.Run("missing file declines", func(t *testing.T) {
		_, err := p.Resolve(context.Background())
		if !errors.Is(err, attestation.ErrNoIdentity) {
			t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
		}
	})

	t.Run("existing file resolves trimmed contents", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("  agent-y\n"), 0o600); err != nil {
			t.Fatalf("setup: write identity file: %v", err)
		}
		id, err := p.Resolve(context.Background())
		if err != nil {
			t.Fatalf("Resolve(): unexpected error: %v", err)
		}
		if id.Subject != "agent-y" {
			t.Errorf("Subject = %q, want %q", id.Subject, "agent-y")
		}
		if id.Source != "configured" {
			t.Errorf("Source = %q, want %q", id.Source, "configured")
		}
	})

	t.Run("empty file declines", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
			t.Fatalf("setup: write identity file: %v", err)
		}
		_, err := p.Resolve(context.Background())
		if !errors.Is(err, attestation.ErrNoIdentity) {
			t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
		}
	})
}
