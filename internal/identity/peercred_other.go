//go:build !linux

package identity

import (
	"errors"
	"net"
)

// peerCred has no portable implementation; serve refuses every connection
// rather than guess a peer.
func peerCred(*net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("SO_PEERCRED is only supported on linux")
}
