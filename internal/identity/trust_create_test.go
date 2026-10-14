//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The trust check judges the final mode, not the mode mkdir produced under the
// umask: a group-writable createMode must not slip through a 022 umask.
func TestTrustRootCreatedWithAWritableModeIsRefused(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"group": 0o775, "other": 0o757, "both": 0o777} {
		p := filepath.Join(base, name)
		d, err := openTrustedDir(p, mode)
		if err == nil {
			d.Close()
			t.Fatalf("%s-writable create mode %#o produced an accepted trust root", name, mode)
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: refusal does not name the path: %v", name, err)
		}
		if _, serr := os.Stat(p); serr == nil {
			t.Errorf("%s: a refused start left %s behind", name, p)
		}
	}
}

func TestTrustRootCreatedPrivateEndsAtItsRequestedMode(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	base := t.TempDir()
	p := filepath.Join(base, "made")
	d, err := openTrustedDir(p, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, %v", fi, err)
	}
}
