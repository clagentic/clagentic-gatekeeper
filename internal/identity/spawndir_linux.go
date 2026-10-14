//go:build linux

package identity

import (
	"fmt"
	"os"
	"syscall"
)

// publishRelative writes identity.jwt and tmp/ into the delivery directory name,
// opened relative to the spawn root handle without following links, then hands
// file, tmp/ and the directory to the peer in that order. The directory stays
// serving-uid owned, mode 0700, until the final chown, so no other uid can race
// an entry into it.
func publishRelative(rootfd int, name string, peer Peer, content []byte) error {
	dfd, err := syscall.Openat(rootfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open delivery directory %s: %w", name, err)
	}
	defer syscall.Close(dfd)

	var st syscall.Stat_t
	if err := syscall.Fstat(dfd, &st); err != nil {
		return err
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("delivery directory %s is not owned by the serving uid", name)
	}

	ffd, err := syscall.Openat(dfd, DeliveryFile, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", DeliveryFile, err)
	}
	file := os.NewFile(uintptr(ffd), DeliveryFile)
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}

	// tmp/ is created last and with Mkdirat, which fails on any existing entry
	// including a symlink rather than following it.
	if err := syscall.Mkdirat(dfd, "tmp", 0o700); err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tfd, err := syscall.Openat(dfd, "tmp", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	defer syscall.Close(tfd)

	if needsChown(peer) {
		if err := syscall.Fchown(int(file.Fd()), int(peer.UID), int(peer.GID)); err != nil {
			return handoverError(DeliveryFile, peer, err)
		}
		if err := syscall.Fchown(tfd, int(peer.UID), int(peer.GID)); err != nil {
			return handoverError("tmp", peer, err)
		}
		if err := syscall.Fsync(dfd); err != nil {
			return err
		}
		if err := syscall.Fchown(dfd, int(peer.UID), int(peer.GID)); err != nil {
			return handoverError(name, peer, err)
		}
	}
	return syscall.Fsync(dfd)
}
