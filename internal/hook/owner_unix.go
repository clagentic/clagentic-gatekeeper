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
