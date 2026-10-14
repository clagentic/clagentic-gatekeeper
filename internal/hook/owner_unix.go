//go:build !windows

package hook

import (
	"os"
	"syscall"
)

// ownedByUs reports whether fi belongs to the current user. A file whose owner
// cannot be read is treated as not ours.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// chownLike gives f the owner and group of ref. A file already owned by the
// running user and group needs nothing; any other owner (a root run editing a
// user's file) must be set, and a failure to set it is an error: the replacement
// would otherwise be left owned by the wrong user.
func chownLike(f *os.File, ref os.FileInfo) error {
	st, ok := ref.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) == os.Geteuid() && int(st.Gid) == os.Getegid() {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}

// syncDir flushes a directory so a rename in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
