//go:build linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// The package-wide rule: serve never acts on, or decides from, filesystem
// state a uid other than the serving uid or root can write. Every trust root
// (signing key, definitions, spawn root, socket directory, key set directory)
// is therefore opened once, at start, by openTrustedDir, which walks from "/"
// one descriptor at a time and refuses the start when any directory on the way
// is owned by someone else or writable by group or other. Everything serve
// later reads, writes, chmods, chowns or removes is reached relative to that
// descriptor, so a rename or symlink swap of a path component afterwards
// cannot redirect it.

const (
	atRemoveDir = 0x200 // AT_REMOVEDIR
	sticky      = 0o1000
)

// maxRemoveDepth bounds the descriptors held while removing a nested tree.
const maxRemoveDepth = 128

// trustedOwner reports whether uid may own something serve trusts: root or the
// serving uid.
func trustedOwner(uid uint32) bool { return uid == 0 || int(uid) == os.Geteuid() }

// checkTrustedDir fails unless the directory behind fd is owned by root or the
// serving uid and is not writable by group or other. An ancestor with the
// sticky bit (the shape of a shared temporary directory) may be world-writable:
// other uids cannot rename or remove an entry they do not own, and the next
// component is verified in turn. The trust root itself never gets that
// allowance, because serve creates entries in it.
func checkTrustedDir(fd int, path string, isRoot bool) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if !trustedOwner(st.Uid) {
		return fmt.Errorf("%s is owned by uid %d; it must be owned by root or the serving uid", path, st.Uid)
	}
	if st.Mode&0o022 != 0 && (isRoot || st.Mode&sticky == 0) {
		return fmt.Errorf("%s is writable by group or other (mode %#o); remove that write permission", path, st.Mode&0o7777)
	}
	return nil
}

// openTrustedDir returns a handle on the absolute directory path after
// verifying it and every ancestor. The final component is created with
// createMode when it is missing and createMode is non-zero; no other missing
// component is created. A symbolic link anywhere on the path is refused, so
// configure the real path.
func openTrustedDir(path string, createMode os.FileMode) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%q must be an absolute path", path)
	}
	clean := filepath.Clean(path)
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var parts []string
	if clean != "/" {
		parts = strings.Split(strings.TrimPrefix(clean, "/"), "/")
	}
	fail := func(err error) (*os.File, error) {
		syscall.Close(fd)
		return nil, err
	}
	if err := checkTrustedDir(fd, "/", len(parts) == 0); err != nil {
		return fail(err)
	}
	cur := ""
	for i, part := range parts {
		cur += "/" + part
		isRoot := i == len(parts)-1
		const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		next, err := syscall.Openat(fd, part, flags, 0)
		created := false
		if errors.Is(err, syscall.ENOENT) && isRoot && createMode != 0 {
			if err := syscall.Mkdirat(fd, part, uint32(createMode.Perm())); err != nil {
				return fail(fmt.Errorf("create %s: %w", cur, err))
			}
			created = true
			next, err = syscall.Openat(fd, part, flags, 0)
		}
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
				err = errors.New("not a directory, or a symbolic link (configure the real path)")
			}
			return fail(fmt.Errorf("%s: %w", cur, err))
		}
		syscall.Close(fd)
		fd = next
		if created {
			// The mode given to mkdir is filtered by the umask.
			if err := syscall.Fchmod(fd, uint32(createMode.Perm())); err != nil {
				return fail(fmt.Errorf("set mode of %s: %w", cur, err))
			}
		}
		if err := checkTrustedDir(fd, cur, isRoot); err != nil {
			return fail(err)
		}
	}
	return os.NewFile(uintptr(fd), clean), nil
}

// reopen returns a new handle on the directory dir refers to, with its own
// read offset, so listing it never disturbs another reader of dir.
func reopen(dir *os.File) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), dir.Name()), nil
}

// unlinkatDir removes the empty directory name inside dirfd.
func unlinkatDir(dirfd int, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), atRemoveDir)
	if e != 0 {
		return e
	}
	return nil
}

// removeAt removes name and everything below it, relative to dirfd, without
// following a link at any level and without consulting the path of anything.
// A missing entry is not an error.
func removeAt(dirfd int, name string) error { return removeAtDepth(dirfd, name, 0) }

func removeAtDepth(dirfd int, name string, depth int) error {
	err := syscall.Unlinkat(dirfd, name)
	if err == nil || errors.Is(err, syscall.ENOENT) {
		return nil
	}
	// Linux answers EISDIR for a directory; POSIX allows EPERM.
	if !errors.Is(err, syscall.EISDIR) && !errors.Is(err, syscall.EPERM) {
		return err
	}
	if depth >= maxRemoveDepth {
		return fmt.Errorf("%s is nested deeper than %d levels", name, maxRemoveDepth)
	}
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return err
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	// A peer that owns the tree can add entries while it is emptied; a few
	// passes cover that, and a tree that keeps growing is reported.
	for pass := 0; pass < 4; pass++ {
		names, err := dir.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, child := range names {
			if err := removeAtDepth(fd, child, depth+1); err != nil {
				return err
			}
		}
		err = unlinkatDir(dirfd, name)
		if err == nil || errors.Is(err, syscall.ENOENT) {
			return nil
		}
		if !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
		if _, serr := dir.Seek(0, 0); serr != nil {
			return serr
		}
	}
	return fmt.Errorf("%s kept gaining entries while it was removed", name)
}
