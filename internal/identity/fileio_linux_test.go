package identity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked", what)
	}
}

func TestSigningKeyThroughASymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	real := writeKey(t, dir, "real.pem", false)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(link, "", nil); err == nil {
		t.Fatal("a symlinked signing key was loaded")
	}
}

func TestSigningKeyThatIsAFIFOIsRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "key.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	within(t, "LoadKeyring on a FIFO", func() {
		if _, err := LoadKeyring(fifo, "", nil); err == nil {
			t.Error("a FIFO signing key was loaded")
		}
	})
}

func TestSelfCheckWithAFIFOJWKSPathFailsWithoutBlocking(t *testing.T) {
	c, _ := startServer(t, nil)
	fifo := filepath.Join(t.TempDir(), "jwks.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	within(t, "SelfCheck on a FIFO jwks_path", func() {
		checks := SelfCheck(c, fifo, 0, testNow)
		last := checks[len(checks)-1]
		if last.Name != "jwks_fresh" || last.OK {
			t.Errorf("checks %+v", checks)
		}
	})
}
