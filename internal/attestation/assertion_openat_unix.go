//go:build unix

package attestation

import (
	"os"

	"golang.org/x/sys/unix"
)

// openAt opens name relative to the directory handle dir, never following a
// link at the final component. The lookup starts at the handle, so no path of
// the directory is consulted after it was validated. The standard syscall
// package has openat on linux only; golang.org/x/sys/unix has it on every unix
// GOOS, so no platform falls back to opening by path.
func openAt(dir *os.File, name string) (int, error) {
	return unix.Openat(int(dir.Fd()), name, openFileFlags, 0)
}
