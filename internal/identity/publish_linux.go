//go:build linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// unlinkat is syscall.Unlinkat unless a test needs a removal failure the
// filesystem cannot produce on demand.
var unlinkat = syscall.Unlinkat

// fsyncDir is syscall.Fsync unless a test needs to see whether the directory
// flush ran.
var fsyncDir = syscall.Fsync

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
//
// A failure to remove the temporary name is part of the result: it is joined to
// the error that caused the cleanup, or returned on its own when the file was
// published.
func publishFileAt(dfd int, name string, content []byte, mode os.FileMode, replace bool) (err error) {
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
	removeTmp := func() error {
		if !tmpExists {
			return nil
		}
		tmpExists = false
		if err := unlinkat(dfd, tmpName); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("remove temporary %s: %w", tmpName, err)
		}
		return nil
	}
	defer func() {
		// The explicit Close below already reported a failed flush; this one
		// only covers the early returns, where the file is discarded anyway.
		_ = tmp.Close()
		if cerr := removeTmp(); cerr != nil {
			err = errors.Join(err, cerr)
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
		// link(2) never replaces, which is the no-overwrite rename. It leaves the
		// temporary name as a second hard link, so that name is removed at once:
		// a crash after this point leaves the complete file under its final name
		// and, but for the instant between the two calls, nothing else.
		if err := linkat(dfd, tmpName, dfd, name); err != nil {
			return fmt.Errorf("publish %s: %w", name, err)
		}
		// The final name exists now, so a failed removal must not skip the
		// directory flush below; both outcomes are reported.
		if rerr := removeTmp(); rerr != nil {
			return errors.Join(rerr, flushDir(dfd, name))
		}
	}
	// Past this point the final name exists; a failed flush is reported.
	return flushDir(dfd, name)
}

func flushDir(dfd int, name string) error {
	if err := fsyncDir(dfd); err != nil {
		return fmt.Errorf("flush the directory of %s: %w", name, err)
	}
	return nil
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
