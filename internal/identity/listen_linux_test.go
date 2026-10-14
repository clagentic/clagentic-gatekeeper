package identity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The path carries socket_mode from the moment it exists, whatever the process
// umask is: it is created by linking a socket whose mode was already set.
func TestListenPublishesTheFinalPathWithTheConfiguredModeUnderAnyUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	l, err := Listen(path, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o666 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("mode %v, want a socket with 0666", fi.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary names left behind: %v %v", entries, err)
	}
}
