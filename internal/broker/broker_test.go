package broker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestEnvBroker verifies that envbroker reads a set variable and errors on unset.
func TestEnvBroker(t *testing.T) {
	const varName = "BROKER_TEST_ENV_VAR_LR9425"
	const wantVal = "supersecret"

	// Precondition: variable must be absent before we set it.
	os.Unsetenv(varName)

	b := &envbroker{}
	ctx := context.Background()

	t.Run("unset variable returns error", func(t *testing.T) {
		_, err := b.Get(ctx, varName)
		if err == nil {
			t.Fatal("expected error for unset variable, got nil")
		}
	})

	t.Run("set variable returns value", func(t *testing.T) {
		t.Setenv(varName, wantVal)
		got, err := b.Get(ctx, varName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != wantVal {
			t.Fatalf("got %q, want %q", got, wantVal)
		}
	})

	t.Run("empty variable returns error", func(t *testing.T) {
		t.Setenv(varName, "")
		_, err := b.Get(ctx, varName)
		if err == nil {
			t.Fatal("expected error for empty variable, got nil")
		}
	})
}

// TestFileBroker verifies that filebroker reads a temp file and errors on missing path.
func TestFileBroker(t *testing.T) {
	b := &filebroker{}
	ctx := context.Background()

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := b.Get(ctx, filepath.Join(t.TempDir(), "nonexistent-file"))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("existing file returns trimmed contents", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "secret.txt")
		// Write with surrounding whitespace to verify TrimSpace behaviour.
		if err := os.WriteFile(p, []byte("  my-api-key\n"), 0600); err != nil {
			t.Fatalf("setup: write temp file: %v", err)
		}

		got, err := b.Get(ctx, p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		const want = "my-api-key"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// TestNew_knownTypes verifies that New() dispatches correctly for env and file
// (no-network types) and rejects unknown types.
func TestNew_knownTypes(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		b, err := New(Config{Type: "env"})
		if err != nil {
			t.Fatalf("New(env): %v", err)
		}
		if _, ok := b.(*envbroker); !ok {
			t.Fatalf("expected *envbroker, got %T", b)
		}
	})

	t.Run("file", func(t *testing.T) {
		b, err := New(Config{Type: "file"})
		if err != nil {
			t.Fatalf("New(file): %v", err)
		}
		if _, ok := b.(*filebroker); !ok {
			t.Fatalf("expected *filebroker, got %T", b)
		}
	})

	t.Run("openbao missing endpoint", func(t *testing.T) {
		_, err := New(Config{Type: "openbao", Auth: "token"})
		if err == nil {
			t.Fatal("expected error for openbao without endpoint")
		}
	})

	t.Run("vault missing endpoint", func(t *testing.T) {
		_, err := New(Config{Type: "vault", Auth: "token"})
		if err == nil {
			t.Fatal("expected error for vault without endpoint")
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := New(Config{Type: "notabroker"})
		if err == nil {
			t.Fatal("expected error for unknown broker type")
		}
	})
}
