//go:build unix && !linux

package identity

import (
	"fmt"
	"os"
	"syscall"
)

// OpenRegularFile opens the file at path through one non-blocking handle that
// does not follow a link at the final component, and returns it with the fstat
// of that same handle. See the linux implementation.
func OpenRegularFile(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	return f, fi, nil
}
