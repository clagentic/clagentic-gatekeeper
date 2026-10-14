package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DeliveryFile is the file name the contract's section 6 fixes.
const DeliveryFile = "identity.jwt"

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SpawnDirs creates delivery directories under Root.
type SpawnDirs struct {
	Root string

	// lstat is os.Lstat unless a test needs a failure the filesystem cannot
	// produce on demand.
	lstat func(string) (fs.FileInfo, error)
}

// Ensure creates Root. It is 0711 so every peer can walk to its own
// directory without being able to list the others.
func (s SpawnDirs) Ensure() error {
	if !filepath.IsAbs(s.Root) {
		return fmt.Errorf("spawn root %q must be absolute", s.Root)
	}
	if err := os.MkdirAll(s.Root, 0o711); err != nil {
		return err
	}
	return os.Chmod(s.Root, 0o711)
}

// Create makes a 0700 directory owned by the serving uid and returns its
// absolute path. The peer cannot enter it, so it cannot plant anything in it,
// until Publish hands it over as the very last step.
func (s SpawnDirs) Create() (string, error) {
	if !filepath.IsAbs(s.Root) {
		return "", fmt.Errorf("spawn root %q must be absolute", s.Root)
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// Publish fills a directory made by Create and then hands it to the peer. The
// privileged writer never follows a path the peer could own: the directory is
// opened O_NOFOLLOW, every entry is created relative to that descriptor with
// O_EXCL, and ownership moves to the peer only after the content is written
// and synced.
func (s SpawnDirs) Publish(dir string, peer Peer, token string) error {
	if filepath.Dir(filepath.Clean(dir)) != filepath.Clean(s.Root) {
		return fmt.Errorf("%s is not a direct child of the spawn root", dir)
	}
	return publishRelative(dir, peer, []byte(token+"\n"))
}

func needsChown(peer Peer) bool {
	return int(peer.UID) != os.Geteuid() || int(peer.GID) != os.Getegid()
}

func handoverError(what string, peer Peer, err error) error {
	return fmt.Errorf("hand %s to uid %d (serve needs root or CAP_CHOWN to serve another uid): %w", what, peer.UID, err)
}

// Discard removes a directory this package created; it refuses anything that
// is not a direct child of Root.
func (s SpawnDirs) Discard(dir string) error { return s.discard(dir) }

func (s SpawnDirs) discard(dir string) error {
	if filepath.Dir(filepath.Clean(dir)) != filepath.Clean(s.Root) {
		return fmt.Errorf("%s is not a direct child of the spawn root", dir)
	}
	return os.RemoveAll(dir)
}

// Reap removes delivery directories untouched for longer than maxAge. An
// assertion lives at most MaxLifetimeSeconds, so a directory idle for twice
// that holds nothing a holder can still use.
//
// Only an entry that vanished between listing and inspection (ENOENT) is
// ignored. Any other Lstat or removal failure is collected, the sweep carries
// on with the remaining entries, and the joined error is returned so the
// caller can log that stale directories remain.
func (s SpawnDirs) Reap(now time.Time, maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return 0, err
	}
	lstat := s.lstat
	if lstat == nil {
		lstat = os.Lstat
	}
	removed := 0
	var failures []error
	for _, e := range entries {
		path := filepath.Join(s.Root, e.Name())
		fi, err := lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect %s: %w", e.Name(), err))
			continue
		}
		if !fi.IsDir() {
			continue
		}
		if now.Sub(fi.ModTime()) > maxAge {
			if err := s.discard(path); err != nil {
				failures = append(failures, fmt.Errorf("remove %s: %w", e.Name(), err))
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(failures...)
}
