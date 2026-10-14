//go:build linux

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openRegular opens path for reading and returns the open file with the
// result of fstat on that same descriptor. It never blocks and never follows
// a link: O_NONBLOCK stops a FIFO from holding the open, O_NOFOLLOW refuses a
// symlink in the final component, and anything that is not a regular file is
// refused after the fstat. Callers validate and read through the returned
// file, so what they check is what they read.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Base(path))
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
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
