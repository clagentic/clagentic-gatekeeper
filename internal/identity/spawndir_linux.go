//go:build linux

package identity

import (
	"fmt"
	"os"
	"syscall"
)

// publishRelative writes identity.jwt and tmp/ into the delivery directory name,
// opened relative to the spawn root handle without following links. The
// directory is serving-uid owned, mode 0700, and the peer is that uid.
func publishRelative(rootfd int, name string, content []byte) error {
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

	// The token is on disk before identity.jwt exists under its name, and the
	// no-replace publish never overwrites a pre-existing entry.
	if err := publishFileAt(dfd, DeliveryFile, content, 0o600, false); err != nil {
		return err
	}

	// tmp/ is created last and with Mkdirat, which fails on any existing entry
	// including a symlink rather than following it.
	if err := syscall.Mkdirat(dfd, "tmp", 0o700); err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	if err := syscall.Fsync(dfd); err != nil {
		return err
	}
	// The directory's own entry in the spawn root is flushed last.
	return syscall.Fsync(rootfd)
}
