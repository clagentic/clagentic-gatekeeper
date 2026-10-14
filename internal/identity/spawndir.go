//go:build linux

package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// spawnNamePattern is the name Create gives a delivery directory: the creation
// time in seconds as hex, then 128 random bits. Reap trusts only this name for
// age, because the root is closed to every other uid and the name never changes
// after creation, unlike the metadata of a directory its peer owns.
var spawnNamePattern = regexp.MustCompile(`^([0-9a-f]{10})-[0-9a-f]{32}$`)

// probeName is the scratch directory CheckRemovable uses; it does not match
// spawnNamePattern, so Reap never mistakes it for a delivery directory.
const probeName = ".probe"

// SpawnDirs creates delivery directories under Root. It holds a handle on Root
// opened at start, and creates, fills, hands over and removes everything
// relative to that handle.
type SpawnDirs struct {
	Root string
	root *os.File

	// remove is removeAt unless a test needs a failure the filesystem cannot
	// produce on demand.
	remove func(dirfd int, name string) error
}

// NewSpawnDirs opens root as a trust root, creating the final component when
// it is missing. Root is 0711 so every peer can walk to its own directory
// without being able to list the others.
func NewSpawnDirs(root string) (*SpawnDirs, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("spawn root %q must be absolute", root)
	}
	h, err := openTrustedDir(root, 0o711)
	if err != nil {
		return nil, fmt.Errorf("spawn root: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(h.Fd()), &st); err != nil {
		h.Close()
		return nil, err
	}
	if int(st.Uid) == os.Geteuid() {
		if err := syscall.Fchmod(int(h.Fd()), 0o711); err != nil {
			h.Close()
			return nil, err
		}
	}
	return &SpawnDirs{Root: filepath.Clean(root), root: h}, nil
}

// Close releases the handle on Root.
func (s *SpawnDirs) Close() error { return s.root.Close() }

func (s *SpawnDirs) rm() func(int, string) error {
	if s.remove != nil {
		return s.remove
	}
	return removeAt
}

// Create makes a 0700 directory owned by the serving uid, named from now, and
// returns its absolute path. The peer cannot enter it, so it cannot plant
// anything in it, until Publish hands it over as the very last step.
func (s *SpawnDirs) Create(now time.Time) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%010x-%s", now.Unix(), id)
	dir := filepath.Join(s.Root, name)
	if err := syscall.Mkdirat(int(s.root.Fd()), name, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// nameOf returns the entry name of dir when dir is a direct child of Root.
func (s *SpawnDirs) nameOf(dir string) (string, error) {
	if filepath.Dir(filepath.Clean(dir)) != s.Root {
		return "", fmt.Errorf("%s is not a direct child of the spawn root", dir)
	}
	return filepath.Base(dir), nil
}

// Publish fills a directory made by Create and then hands it to the peer. The
// privileged writer never follows a path the peer could own: the directory is
// opened relative to the root handle with O_NOFOLLOW, every entry is created
// relative to that descriptor with O_EXCL, and ownership moves to the peer only
// after the content is written and synced.
func (s *SpawnDirs) Publish(dir string, peer Peer, token string) error {
	name, err := s.nameOf(dir)
	if err != nil {
		return err
	}
	return publishRelative(int(s.root.Fd()), name, peer, []byte(token+"\n"))
}

func needsChown(peer Peer) bool {
	return int(peer.UID) != os.Geteuid() || int(peer.GID) != os.Getegid()
}

func handoverError(what string, peer Peer, err error) error {
	return fmt.Errorf("hand %s to uid %d (serve needs root or CAP_CHOWN to serve another uid): %w", what, peer.UID, err)
}

// Discard removes a directory this package created, relative to the root
// handle; it refuses anything that is not a direct child of Root.
func (s *SpawnDirs) Discard(dir string) error {
	name, err := s.nameOf(dir)
	if err != nil {
		return err
	}
	return s.rm()(int(s.root.Fd()), name)
}

// Reap removes delivery directories created more than maxAge ago. An assertion
// lives at most MaxLifetimeSeconds, so a directory older than twice that holds
// nothing a holder can still use.
//
// Age is read from the entry name Create chose, never from a directory's
// metadata, which the peer that owns the directory can set to anything. Entries
// that do not carry that name are not ours and are left alone.
//
// Only an entry that vanished meanwhile (ENOENT) is ignored. Any other removal
// failure is collected, the sweep carries on with the remaining entries, and the
// joined error is returned so the caller can log that stale directories remain.
func (s *SpawnDirs) Reap(now time.Time, maxAge time.Duration) (int, error) {
	scan, err := reopen(s.root)
	if err != nil {
		return 0, err
	}
	defer scan.Close()
	names, err := scan.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	removed := 0
	var failures []error
	for _, name := range names {
		m := spawnNamePattern.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		created, err := strconv.ParseInt(m[1], 16, 64)
		if err != nil || now.Sub(time.Unix(created, 0)) <= maxAge {
			continue
		}
		err = s.rm()(int(s.root.Fd()), name)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("remove %s: %w", name, err))
			continue
		}
		removed++
	}
	return removed, errors.Join(failures...)
}

// CheckRemovable proves, before serve accepts a request, that it can remove
// what it will hand to the given uids and gids: a directory owned by that uid
// or gid, holding a nested subdirectory of mode 0000. Without that ability a
// reaped or discarded delivery directory would stay behind, so serve refuses to
// start instead. Nothing is probed for the serving uid and gid themselves.
func (s *SpawnDirs) CheckRemovable(uids, gids []uint32) error {
	type owner struct{ uid, gid int }
	var targets []owner
	for _, u := range uids {
		if int(u) != os.Geteuid() {
			targets = append(targets, owner{int(u), -1})
		}
	}
	for _, g := range gids {
		if int(g) != os.Getegid() {
			targets = append(targets, owner{-1, int(g)})
		}
	}
	for _, t := range targets {
		if err := s.probe(t.uid, t.gid); err != nil {
			return err
		}
	}
	return nil
}

func (s *SpawnDirs) probe(uid, gid int) error {
	rootfd := int(s.root.Fd())
	who := "uid " + strconv.Itoa(uid)
	if uid < 0 {
		who = "gid " + strconv.Itoa(gid)
	}
	if err := removeAt(rootfd, probeName); err != nil {
		return fmt.Errorf("clear a leftover %s in the spawn root: %w", probeName, err)
	}
	if err := syscall.Mkdirat(rootfd, probeName, 0o700); err != nil {
		return fmt.Errorf("probe the spawn root: %w", err)
	}
	defer removeAt(rootfd, probeName)
	const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	pfd, err := syscall.Openat(rootfd, probeName, flags, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(pfd)
	if err := syscall.Mkdirat(pfd, "nested", 0o700); err != nil {
		return err
	}
	nfd, err := syscall.Openat(pfd, "nested", flags, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(nfd)
	for _, fd := range []int{nfd, pfd} {
		if err := syscall.Fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("hand a probe directory to %s (serve needs root or CAP_CHOWN to serve another uid or gid): %w", who, err)
		}
	}
	// Locked last: a failed handover above must leave a tree the serving uid
	// can still remove.
	if err := syscall.Fchmod(nfd, 0); err != nil {
		return err
	}
	if err := removeAt(rootfd, probeName); err != nil {
		return fmt.Errorf("serve cannot remove a directory tree owned by %s (it needs root, or CAP_DAC_OVERRIDE and CAP_FOWNER): %w", who, err)
	}
	return nil
}
