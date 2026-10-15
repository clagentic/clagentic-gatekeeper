//go:build unix

package attestation

import (
	"errors"
	"io"
	"os"
	"path"
	"syscall"
)

var (
	errFileMissing  = errors.New("file does not exist")
	errFileLink     = errors.New("file is a symlink or not a regular file")
	errFileTooLarge = errors.New("file is too large")
)

const openFileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// afterDirValidated runs between validating the delivery directory handle and
// opening the assertion relative to it. It is nil outside tests, where it
// stands in for an attacker who swaps the path in that window.
var afterDirValidated func()

// readFileNoFollow opens p through one handle that never follows a link at the
// final component and never blocks, checks that same handle is a regular file,
// and reads at most max bytes. Checking the handle rather than the path means
// what is validated is what is read. It returns the handle's FileInfo.
func readFileNoFollow(p string, max int) ([]byte, os.FileInfo, error) {
	fd, err := syscall.Open(p, openFileFlags, 0)
	return readOpened(fd, err, p, max)
}

// readFileAt is readFileNoFollow for name inside the directory open as dir:
// the lookup is relative to that handle, so a rename of the directory's path
// cannot redirect it.
func readFileAt(dir *os.File, name string, max int) ([]byte, os.FileInfo, error) {
	fd, err := openAt(dir, name)
	return readOpened(fd, err, name, max)
}

func readOpened(fd int, openErr error, name string, max int) ([]byte, os.FileInfo, error) {
	if errors.Is(openErr, syscall.ENOENT) {
		return nil, nil, errFileMissing
	}
	if errors.Is(openErr, syscall.ELOOP) {
		// ELOOP is what O_NOFOLLOW reports for a symlink.
		return nil, nil, errFileLink
	}
	if openErr != nil {
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: openErr}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errFileLink
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > max {
		return nil, nil, errFileTooLarge
	}
	return data, fi, nil
}

// openDeliveryDir opens the delivery directory without following a link at
// its final component and returns the handle. Every later check and read goes
// through this handle, never through the path again.
func openDeliveryDir(dir string) (*os.File, *AssertionError) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	switch {
	case err == nil:
		return os.NewFile(uintptr(fd), dir), nil
	case errors.Is(err, syscall.ENOENT):
		return nil, refuseAssertion(CodeDirMissing, "%s names a directory that does not exist", IdentityDirEnv)
	case errors.Is(err, syscall.ELOOP):
		return nil, refuseAssertion(CodeDirUnsafe, "the delivery directory is a symlink")
	case errors.Is(err, syscall.ENOTDIR):
		// O_DIRECTORY|O_NOFOLLOW reports a symlink and a plain file alike.
		if li, lerr := os.Lstat(dir); lerr == nil && li.Mode()&os.ModeSymlink != 0 {
			return nil, refuseAssertion(CodeDirUnsafe, "the delivery directory is a symlink")
		}
		return nil, refuseAssertion(CodeDirMissing, "%s does not name a directory", IdentityDirEnv)
	}
	return nil, refuseAssertion(CodeDirUnsafe, "cannot inspect the delivery directory: %v", err)
}

// readDelivery applies the delivery checks of the contract's section 6 and
// returns the assertion bytes without the one optional trailing newline.
func readDelivery(dir string) ([]byte, *AssertionError) {
	if !path.IsAbs(dir) {
		return nil, refuseAssertion(CodeDirMissing, "%s is not an absolute path", IdentityDirEnv)
	}
	d, aerr := openDeliveryDir(dir)
	if aerr != nil {
		return nil, aerr
	}
	defer d.Close()
	info, err := d.Stat()
	if err != nil {
		return nil, refuseAssertion(CodeDirUnsafe, "cannot inspect the delivery directory: %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0o700 {
		return nil, refuseAssertion(CodeDirUnsafe, "the delivery directory is not owned by this user with mode 0700")
	}
	if afterDirValidated != nil {
		afterDirValidated()
	}
	data, _, err := readFileAt(d, AssertionFile, maxAssertionFileBytes)
	switch {
	case errors.Is(err, errFileMissing):
		return nil, refuseAssertion(CodeFileMissing, "%s is not in the delivery directory", AssertionFile)
	case errors.Is(err, errFileLink):
		return nil, refuseAssertion(CodeFileSymlink, "%s is a symlink or not a regular file", AssertionFile)
	case errors.Is(err, errFileTooLarge):
		return nil, refuseAssertion(CodeMalformed, "%s is larger than %d bytes", AssertionFile, maxAssertionFileBytes)
	case err != nil:
		return nil, refuseAssertion(CodeFileMissing, "cannot read %s: %v", AssertionFile, err)
	}
	if n := len(data); n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
	}
	return data, nil
}
