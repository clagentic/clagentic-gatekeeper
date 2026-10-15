//go:build unix && !linux

package attestation

import (
	"errors"
	"os"
	"path"
	"syscall"
)

var errDeliveryDirMoved = errors.New("the delivery directory was replaced while it was read")

// openAt opens name in the directory dir was opened from. The standard
// syscall package has no openat on these platforms and the module takes no
// dependency for one, so the file is opened by path and the path is then
// required to still name the validated directory object. A rename of the
// directory in the instant between the two is the one window this leaves; the
// directory is owner-only, so only the verifier's own user can open it.
func openAt(dir *os.File, name string) (int, error) {
	fd, err := syscall.Open(path.Join(dir.Name(), name), openFileFlags, 0)
	if err != nil {
		return -1, err
	}
	want, serr := dir.Stat()
	now, lerr := os.Lstat(dir.Name())
	if serr != nil || lerr != nil || !os.SameFile(want, now) {
		syscall.Close(fd)
		return -1, errDeliveryDirMoved
	}
	return fd, nil
}
