//go:build !linux

package identity

import "errors"

// publishRelative has no portable implementation; serve already refuses every
// connection off linux because SO_PEERCRED is unavailable.
func publishRelative(string, Peer, []byte) error {
	return errors.New("delivery directories are only supported on linux")
}
