//go:build !unix

package attestation

import (
	"errors"
	"os"
)

var (
	errFileMissing  = errors.New("file does not exist")
	errFileLink     = errors.New("file is a symlink or not a regular file")
	errFileTooLarge = errors.New("file is too large")
)

var errNoFollowUnsupported = errors.New("opening a file without following a final-component link is not supported on this platform")

// readFileNoFollow always refuses off unix: a link at the final component
// cannot be refused through the handle os.Open returns, and the contract
// requires it. Refusing keeps the contract of the other platforms.
func readFileNoFollow(string, int) ([]byte, os.FileInfo, error) {
	return nil, nil, errNoFollowUnsupported
}

// readDelivery refuses off unix: directory ownership cannot be compared with
// the verifier's uid there, so a delivery cannot be proven safe.
func readDelivery(string) ([]byte, *AssertionError) {
	return nil, refuseAssertion(CodeDirUnsafe, "assertion delivery is not supported on this platform")
}
