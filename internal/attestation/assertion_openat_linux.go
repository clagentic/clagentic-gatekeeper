//go:build linux

package attestation

import (
	"os"
	"syscall"
)

// openAt opens name relative to the directory handle dir, never following a
// link at the final component. The lookup starts at the handle, so no path of
// the directory is consulted after it was validated.
func openAt(dir *os.File, name string) (int, error) {
	return syscall.Openat(int(dir.Fd()), name, openFileFlags, 0)
}
