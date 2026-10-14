//go:build linux

package hook

import (
	"os"
	"syscall"
	"testing"
)

// A run as root that edits another user's settings must leave the file owned by
// that user, not by root.
func TestInstallKeepsTheOwnerOfTheFileItReplaces(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a file's owner needs root")
	}
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	const uid, gid = 41234, 41235
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != uid || st.Gid != gid {
		t.Fatalf("owner %d:%d, want %d:%d", st.Uid, st.Gid, uid, gid)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
}
