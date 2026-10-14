//go:build windows

package identity

import (
	"fmt"
	"os"
)

// OpenRegularFile opens the file at path and returns it with the fstat of the
// same handle. Windows has no FIFO to stall the open, so the handle check is the
// whole rule. See the linux implementation.
func OpenRegularFile(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
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
