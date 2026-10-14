//go:build linux

package identity

import (
	"fmt"
	"net"
	"syscall"
)

// peerCred reads SO_PEERCRED from an accepted unix connection.
func peerCred(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if sockErr != nil {
		return Peer{}, fmt.Errorf("SO_PEERCRED: %w", sockErr)
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
