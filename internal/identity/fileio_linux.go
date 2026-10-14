//go:build linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// errNotRegular marks an entry that is a directory, FIFO, device or socket.
var errNotRegular = errors.New("not a regular file")

// isNotRegularEntry reports whether an openRegularAt failure means the entry
// is not a plain file at all (a symlink is refused by O_NOFOLLOW with ELOOP),
// as opposed to a plain file that could not be opened or inspected.
func isNotRegularEntry(err error) bool {
	return errors.Is(err, errNotRegular) || errors.Is(err, syscall.ELOOP)
}

// openRegularAt opens the plain file name inside dir for reading and returns
// the open file with the result of fstat on that same descriptor. It never
// blocks and never follows a link: O_NONBLOCK stops a FIFO from holding the
// open, O_NOFOLLOW refuses a symlink, and anything that is not a regular file
// is refused after the fstat. name must be a single path component. Callers
// validate and read through the returned file, so what they check is what they
// read.
func openRegularAt(dir *os.File, name string) (*os.File, os.FileInfo, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return nil, nil, fmt.Errorf("%q is not a single file name", name)
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	return f, fi, nil
}

// ownerUID reports the uid that owns the file fi describes.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// checkTrustedFile fails unless the file is owned by root or the serving uid
// and is not writable by group or other: a definition anyone else can edit
// would let them choose the roles it grants.
func checkTrustedFile(name string, fi os.FileInfo) error {
	uid, ok := ownerUID(fi)
	if !ok || !trustedOwner(uid) {
		return fmt.Errorf("%s is not owned by root or the serving uid", name)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %#o)", name, fi.Mode().Perm())
	}
	return nil
}
