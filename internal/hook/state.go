package hook

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Record is what a later hook process needs to know about an assertion an
// earlier one obtained. It holds no token: the token stays in the delivery
// directory the issuer wrote.
type Record struct {
	Dir       string `json:"dir"`
	ExpiresAt int64  `json:"expires_at"`
	// Definition is the definition the session was requested under, kept so a
	// refresh asks for the same identity.
	Definition string `json:"definition,omitempty"`
	AgentType  string `json:"agent_type,omitempty"`
}

// Store keeps Records between hook processes, one directory per runtime session.
// A Store whose Root is empty or not absolute is disabled: every method refuses
// before touching the filesystem, so a bad root never resolves against the
// working directory.
type Store struct {
	Root string
}

const sessionFile = "session.json"

func agentFile(agentID string) string { return "agent-" + agentID + ".json" }

// ensureRoot creates the state directory and refuses one that another user
// owns or that group or other can write, because a record names a directory a
// stop event later deletes.
func (s Store) ensureRoot() error {
	if !filepath.IsAbs(s.Root) {
		return fmt.Errorf("state directory %q must be absolute", s.Root)
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return err
	}
	return checkPrivateDir(s.Root)
}

func checkPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a plain directory", path)
	}
	if !ownedByUs(fi) {
		return fmt.Errorf("%s is not owned by this user", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other", path)
	}
	return nil
}

func (s Store) sessionDir(sessionID string) (string, error) {
	if !safeName.MatchString(sessionID) {
		return "", errors.New("session id is not a plain name")
	}
	if err := s.ensureRoot(); err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, checkPrivateDir(dir)
}

// recordPath returns where the record of an agent (or the session when agentID
// is empty) lives.
func (s Store) recordPath(sessionID, agentID string) (string, error) {
	// Both keys are checked here, before anything touches the filesystem, so no
	// call site can skip the check and a bad agent id creates no directory.
	if !safeName.MatchString(sessionID) {
		return "", errors.New("session id is not a plain name")
	}
	if agentID != "" && !safeName.MatchString(agentID) {
		return "", errors.New("agent id is not a plain name")
	}
	dir, err := s.sessionDir(sessionID)
	if err != nil {
		return "", err
	}
	if agentID == "" {
		return filepath.Join(dir, sessionFile), nil
	}
	return filepath.Join(dir, agentFile(agentID)), nil
}

// Get returns the record, and false when there is none.
func (s Store) Get(sessionID, agentID string) (Record, bool, error) {
	path, err := s.recordPath(sessionID, agentID)
	if err != nil {
		return Record{}, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, false, fmt.Errorf("state record %s: %w", path, err)
	}
	return r, true, nil
}

// Put replaces the record.
func (s Store) Put(sessionID, agentID string, r Record) error {
	path, err := s.recordPath(sessionID, agentID)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(filepath.Dir(path), r)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// PutNew stores the record only when none exists and reports whether it did. Two
// hooks that race to deliver for one agent therefore agree on a winner.
func (s Store) PutNew(sessionID, agentID string, r Record) (bool, error) {
	path, err := s.recordPath(sessionID, agentID)
	if err != nil {
		return false, err
	}
	tmp, err := writeTemp(filepath.Dir(path), r)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	// link(2) never replaces, so exactly one racer creates the name.
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Delete removes a record; a missing one is not an error.
func (s Store) Delete(sessionID, agentID string) error {
	path, err := s.recordPath(sessionID, agentID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeTemp(dir string, r Record) (string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(nonce[:]))
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return "", err
	}
	return tmp, nil
}

// Prune removes session directories untouched for longer than maxAge. An
// assertion lives at most twelve hours, so a session directory a day old
// describes nothing usable. Only plain-named entries are considered.
func (s Store) Prune(now time.Time, maxAge time.Duration) {
	if s.ensureRoot() != nil {
		return
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !safeName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) <= maxAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(s.Root, e.Name()))
	}
}
