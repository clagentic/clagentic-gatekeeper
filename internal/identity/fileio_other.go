//go:build !linux

package identity

import (
	"errors"
	"os"
)

var errFileIOUnsupported = errors.New("identity file handling is only supported on linux")

// openRegular has no portable implementation that also refuses links and
// FIFOs; serve is linux-only, so it fails closed.
func openRegular(string) (*os.File, os.FileInfo, error) {
	return nil, nil, errFileIOUnsupported
}

// ownerUID cannot be answered off linux.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
