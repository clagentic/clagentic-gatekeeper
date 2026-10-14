package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
}

// Ensure creates Root. It is 0711 so every peer can walk to its own
// directory without being able to list the others.
func (s SpawnDirs) Ensure() error {
	if err := os.MkdirAll(s.Root, 0o711); err != nil {
		return err
	}
	return os.Chmod(s.Root, 0o711)
}

// Create makes a 0700 directory owned by the peer with a tmp/ child, and
// returns its absolute path. The directory is handed to the peer before any
// content exists in it.
func (s SpawnDirs) Create(peer Peer) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if err := s.own(dir, peer); err != nil {
		os.Remove(dir)
		return "", err
	}
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		s.discard(dir)
		return "", err
	}
	if err := s.own(tmp, peer); err != nil {
		s.discard(dir)
		return "", err
	}
	return dir, nil
}

func (s SpawnDirs) own(path string, peer Peer) error {
	if int(peer.UID) == os.Geteuid() && int(peer.GID) == os.Getegid() {
		return nil
	}
	if err := os.Lchown(path, int(peer.UID), int(peer.GID)); err != nil {
		return fmt.Errorf("hand %s to uid %d (serve needs root or CAP_CHOWN to serve another uid): %w", filepath.Base(path), peer.UID, err)
	}
	return nil
}

// Publish writes the token into dir by writing tmp/ and renaming over
// identity.jwt, so a reader never sees a partial file.
func (s SpawnDirs) Publish(dir string, peer Peer, token string) error {
	staged := filepath.Join(dir, "tmp", DeliveryFile)
	if err := os.WriteFile(staged, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	if err := s.own(staged, peer); err != nil {
		return err
	}
	return os.Rename(staged, filepath.Join(dir, DeliveryFile))
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
func (s SpawnDirs) Reap(now time.Time, maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		fi, err := os.Lstat(filepath.Join(s.Root, e.Name()))
		if err != nil || !fi.IsDir() {
			continue
		}
		if now.Sub(fi.ModTime()) > maxAge {
			if err := s.discard(filepath.Join(s.Root, e.Name())); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}
