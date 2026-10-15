//go:build windows

package identity

import (
	"errors"
	"os"
)

// errOpenRegularUnsupported is the one answer on Windows. A final-component
// symlink or reparse point cannot be refused through the handle os.Open returns,
// so a read that must not follow a link cannot be honoured here; refusing is the
// only answer that keeps the contract of the other platforms.
var errOpenRegularUnsupported = errors.New("opening a file without following a final-component link is not supported on windows")

// OpenRegularFile always refuses on Windows. See the linux implementation for
// the contract it cannot meet here.
func OpenRegularFile(path string) (*os.File, os.FileInfo, error) {
	return nil, nil, errOpenRegularUnsupported
}
