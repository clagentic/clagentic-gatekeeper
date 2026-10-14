//go:build linux

package identity

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// publishFileAt is the one way serve makes a file visible under its final name:
// the content is written to a hidden temporary name inside the directory dfd,
// flushed to disk, moved to name, and the directory entry is flushed too. A
// crash therefore leaves either no file or the complete one, never a name that
// points at content not yet on disk.
//
// replace chooses what an existing name does: true overwrites it atomically
// (a key set being refreshed); false fails with EEXIST and leaves it alone (a
// delivery file that must not already be there). Everything is relative to
// dfd and never follows a link.
func publishFileAt(dfd int, name string, content []byte, mode os.FileMode, replace bool) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	tmpName := ".pub-" + id[:16]
	fd, err := syscall.Openat(dfd, tmpName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	tmp := os.NewFile(uintptr(fd), tmpName)
	tmpExists := true
	defer func() {
		tmp.Close()
		if tmpExists {
			_ = syscall.Unlinkat(dfd, tmpName)
		}
	}()
	// Openat's mode is filtered by the umask; fchmod is not.
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if replace {
		if err := syscall.Renameat(dfd, tmpName, dfd, name); err != nil {
			return fmt.Errorf("publish %s: %w", name, err)
		}
		tmpExists = false
	} else {
		// link(2) never replaces, which is the no-overwrite rename.
		if err := linkat(dfd, tmpName, dfd, name); err != nil {
			return fmt.Errorf("publish %s: %w", name, err)
		}
	}
	// Past this point the final name exists; a failed flush or cleanup is
	// reported, and the deferred unlink removes the leftover temporary name.
	return syscall.Fsync(dfd)
}

func linkat(olddirfd int, oldpath string, newdirfd int, newpath string) error {
	op, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(olddirfd), uintptr(unsafe.Pointer(op)), uintptr(newdirfd), uintptr(unsafe.Pointer(np)), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
