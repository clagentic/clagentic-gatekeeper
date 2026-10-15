//go:build !windows

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

// readFileNoFollow opens p through one handle that never follows a link at the
// final component and never blocks, checks that same handle is a regular file,
// and reads at most max bytes. Checking the handle rather than the path means
// what is validated is what is read. It returns the handle's FileInfo.
func readFileNoFollow(p string, max int) ([]byte, os.FileInfo, error) {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil, errFileMissing
	}
	if errors.Is(err, syscall.ELOOP) {
		// ELOOP is what O_NOFOLLOW reports for a symlink.
		return nil, nil, errFileLink
	}
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
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

// readDelivery applies the delivery checks of the contract's section 6 and
// returns the assertion bytes without the one optional trailing newline.
func readDelivery(dir string) ([]byte, *AssertionError) {
	if !path.IsAbs(dir) {
		return nil, refuseAssertion(CodeDirMissing, "%s is not an absolute path", IdentityDirEnv)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, refuseAssertion(CodeDirMissing, "%s names a directory that does not exist", IdentityDirEnv)
	}
	if err != nil {
		return nil, refuseAssertion(CodeDirUnsafe, "cannot inspect the delivery directory: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, refuseAssertion(CodeDirUnsafe, "the delivery directory is a symlink")
	}
	if !info.IsDir() {
		return nil, refuseAssertion(CodeDirMissing, "%s does not name a directory", IdentityDirEnv)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return nil, refuseAssertion(CodeDirUnsafe, "the delivery directory is not owned by this user with mode 0700")
	}
	data, _, err := readFileNoFollow(path.Join(dir, AssertionFile), maxAssertionFileBytes)
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
