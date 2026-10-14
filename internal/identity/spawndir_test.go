//go:build linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newSpawnDirs(t *testing.T) *SpawnDirs {
	t.Helper()
	s, err := NewSpawnDirs(filepath.Join(t.TempDir(), "spawn"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sentinel(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertUntouched(t *testing.T, victim string) {
	t.Helper()
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("victim file changed: %q %v", got, err)
	}
}

func TestPublishCreatesFileAndTmp(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(dir, selfPeer(1), "tok"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, DeliveryFile))
	if err != nil || string(raw) != "tok\n" {
		t.Fatalf("%q %v", raw, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "tmp"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("tmp: %v %v", fi, err)
	}
}

func TestPublishRefusesPlantedSymlinkAtIdentityJWT(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	victim := sentinel(t)
	if err := os.Symlink(victim, filepath.Join(dir, DeliveryFile)); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(dir, selfPeer(1), "tok"); err == nil {
		t.Fatal("publish followed a planted identity.jwt symlink")
	}
	assertUntouched(t, victim)
}

func TestPublishRefusesPlantedSymlinkAtTmpAndNeverWritesThroughIt(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The classic staging path: tmp/identity.jwt reached through a planted tmp.
	targetDir := t.TempDir()
	victim := filepath.Join(targetDir, DeliveryFile)
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, filepath.Join(dir, "tmp")); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(dir, selfPeer(1), "tok"); err == nil {
		t.Fatal("publish followed a planted tmp symlink")
	}
	assertUntouched(t, victim)
	entries, err := os.ReadDir(targetDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("symlink target gained entries: %v %v", entries, err)
	}
}

func TestPublishRefusesPlantedTmpDirectoryHoldingSymlink(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	victim := sentinel(t)
	if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "tmp", DeliveryFile)); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(dir, selfPeer(1), "tok"); err == nil {
		t.Fatal("publish accepted a pre-existing tmp")
	}
	assertUntouched(t, victim)
}

func TestPublishRefusesDirectoryThatIsASymlink(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(dir, selfPeer(1), "tok"); err == nil {
		t.Fatal("publish followed a symlinked delivery directory")
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target gained entries: %v %v", entries, err)
	}
}

func TestReapSurfacesNonENOENTRemovalErrorsAndKeepsSweeping(t *testing.T) {
	s := newSpawnDirs(t)
	old := time.Now().Add(-48 * time.Hour)
	var dirs []string
	for i := 0; i < 3; i++ {
		d, err := s.Create(old)
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
	}
	denied, vanished := filepath.Base(dirs[0]), filepath.Base(dirs[1])
	s.remove = func(fd int, name string) error {
		switch name {
		case denied:
			return syscall.EACCES
		case vanished:
			return syscall.ENOENT
		}
		return removeAt(fd, name)
	}
	removed, err := s.Reap(time.Now(), time.Hour)
	if err == nil || !errors.Is(err, syscall.EACCES) || !strings.Contains(err.Error(), denied) {
		t.Fatalf("a permission error was swallowed: %v", err)
	}
	if errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a vanished entry was reported: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d, want the one reachable stale directory", removed)
	}
	if _, statErr := os.Stat(dirs[2]); !os.IsNotExist(statErr) {
		t.Fatalf("sweep stopped at the failure: %v", statErr)
	}
}

func TestReapLeavesFreshDirectoriesAndReportsNothing(t *testing.T) {
	s := newSpawnDirs(t)
	if _, err := s.Create(time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reap(time.Now(), time.Hour); err != nil || n != 0 {
		t.Fatalf("fresh directory reaped or errored: %d %v", n, err)
	}
}

// Age comes from the name the server chose. The owner of a delivery directory
// controls its mtime, so a directory dated in the future must still be reaped
// once its name says it is old, and a fresh one must not be reaped because its
// mtime says it is old.
func TestReapAgeComesFromTheServerChosenNameNotFromDirectoryMetadata(t *testing.T) {
	s := newSpawnDirs(t)
	stale, err := s.Create(time.Now().Add(-48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(1000 * time.Hour)
	past := time.Now().Add(-1000 * time.Hour)
	if err := os.Chtimes(stale, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, past, past); err != nil {
		t.Fatal(err)
	}
	n, err := s.Reap(time.Now(), time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("reaped %d: %v", n, err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("a future mtime kept a stale directory alive: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("an old mtime got a fresh directory reaped: %v", err)
	}
}

// Only entries carrying the server's own name are its to remove.
func TestReapLeavesEntriesItDidNotName(t *testing.T) {
	s := newSpawnDirs(t)
	foreign := filepath.Join(s.Root, "not-ours")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-1000 * time.Hour)
	if err := os.Chtimes(foreign, old, old); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reap(time.Now().Add(1000*time.Hour), time.Hour); err != nil || n != 0 {
		t.Fatalf("reaped %d: %v", n, err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("an entry the server did not name was removed: %v", err)
	}
}

// A peer-owned tree can hold subdirectories it made unreadable. Removing them
// needs the serving uid to override directory permissions, which root does.
func TestReapRemovesANestedDirectoryOfModeZero(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("removing a mode 0000 directory needs root (DAC override)")
	}
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now().Add(-48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "a", "locked")
	if err := os.MkdirAll(filepath.Join(locked, "deeper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "deeper", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reap(time.Now(), time.Hour); err != nil || n != 1 {
		t.Fatalf("reaped %d: %v", n, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the tree with a mode 0000 subdirectory remains: %v", err)
	}
}

// Removal goes through the handle opened at start. A root renamed away and
// replaced by a link to somewhere else must not steer removal or creation
// there.
func TestRootSwappedAfterStartDoesNotRedirectRemovalOrCreation(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "spawn")
	s, err := NewSpawnDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stale, err := s.Create(time.Now().Add(-48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	staleName := filepath.Base(stale)

	victimDir := filepath.Join(base, "victim")
	if err := os.Mkdir(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A lookalike the swapped root would expose, and an unrelated file.
	lookalike := filepath.Join(victimDir, staleName)
	if err := os.Mkdir(lookalike, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(lookalike, "keep")
	if err := os.WriteFile(keep, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, root); err != nil {
		t.Fatal(err)
	}

	if n, err := s.Reap(time.Now(), time.Hour); err != nil || n != 1 {
		t.Fatalf("reaped %d: %v", n, err)
	}
	assertUntouched(t, keep)
	if _, err := os.Stat(filepath.Join(root+".moved", staleName)); !os.IsNotExist(err) {
		t.Fatalf("the original root was not the one reaped: %v", err)
	}
	created, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(victimDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the swapped-in directory gained entries: %v %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(root+".moved", filepath.Base(created))); err != nil {
		t.Fatalf("Create did not use the root opened at start: %v", err)
	}
}

// A link inside a reaped tree is removed as a link; what it points at is not
// touched.
func TestReapRemovesLinksWithoutFollowingThem(t *testing.T) {
	s := newSpawnDirs(t)
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := s.Create(time.Now().Add(-48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keep, filepath.Join(dir, "filelink")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reap(time.Now(), time.Hour); err != nil || n != 1 {
		t.Fatalf("reaped %d: %v", n, err)
	}
	assertUntouched(t, keep)
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the tree remains: %v", err)
	}
}

// Delivery never changes ownership, so a peer that is not the serving uid is
// refused and the directory is left as created.
func TestPublishRefusesAPeerThatIsNotTheServingUid(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	foreign := selfPeer(1)
	foreign.UID++
	if err := s.Publish(dir, foreign, "tok"); err == nil {
		t.Fatal("publish delivered to another uid")
	}
	if entries, rerr := os.ReadDir(dir); rerr != nil || len(entries) != 0 {
		t.Fatalf("a refused publish wrote entries: %v %v", entries, rerr)
	}
}

// A relative root would make every returned path depend on the working
// directory of the process that later resolves it.
func TestRelativeSpawnRootIsRefused(t *testing.T) {
	if s, err := NewSpawnDirs("relative/spawn"); err == nil {
		s.Close()
		t.Fatal("NewSpawnDirs accepted a relative root")
	}
	if _, err := NewIssuer(Settings{KeyPath: "k", SocketPath: "/run/x.sock", SpawnRoot: "relative/spawn"}); err == nil || !strings.Contains(err.Error(), "identity.spawn_root") {
		t.Fatalf("NewIssuer: %v", err)
	}
}

func TestPublishRefusesDirectoryOutsideRoot(t *testing.T) {
	s := newSpawnDirs(t)
	if err := s.Publish(t.TempDir(), selfPeer(1), "tok"); err == nil {
		t.Fatal("publish accepted a directory outside the spawn root")
	}
	if err := s.Discard(t.TempDir()); err == nil {
		t.Fatal("discard accepted a directory outside the spawn root")
	}
}

func TestSpawnRootWritableByOthersIsRefusedNamingIt(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "spawn")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if s, err := NewSpawnDirs(root); err == nil || !strings.Contains(err.Error(), root) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("got %v, want a refusal naming %s", err, root)
	}
}

// openTrustedDir is the one gate every trust root passes through.
func TestTrustedDirRules(t *testing.T) {
	base := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(base, name)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := mk("ok", 0o755)
	if d, err := openTrustedDir(ok, 0); err != nil {
		t.Fatalf("a private directory was refused: %v", err)
	} else {
		d.Close()
	}
	for name, mode := range map[string]os.FileMode{"group": 0o775, "other": 0o757} {
		p := mk(name, mode)
		if _, err := openTrustedDir(p, 0); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s-writable: got %v", name, err)
		}
		// The same directory as an ancestor is refused too.
		child := filepath.Join(p, "child")
		if err := os.Mkdir(child, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := openTrustedDir(child, 0); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s-writable ancestor: got %v", name, err)
		}
	}
	// A sticky world-writable ancestor (a shared temp dir) is acceptable; the
	// root itself never is.
	shared := mk("shared", 0o777|os.ModeSticky)
	inner := filepath.Join(shared, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if d, err := openTrustedDir(inner, 0); err != nil {
		t.Fatalf("a sticky ancestor was refused: %v", err)
	} else {
		d.Close()
	}
	if _, err := openTrustedDir(shared, 0); err == nil {
		t.Fatal("a sticky world-writable directory was accepted as a trust root")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openTrustedDir(link, 0); err == nil {
		t.Fatal("a symlink was accepted as a trust root")
	}
	if _, err := openTrustedDir("relative", 0); err == nil {
		t.Fatal("a relative path was accepted")
	}
	// Only the final component is ever created.
	if _, err := openTrustedDir(filepath.Join(ok, "a", "b"), 0o755); err == nil {
		t.Fatal("a missing intermediate directory was created")
	}
	if d, err := openTrustedDir(filepath.Join(ok, "made"), 0o700); err != nil {
		t.Fatal(err)
	} else {
		d.Close()
	}
	if fi, err := os.Stat(filepath.Join(ok, "made")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created directory: %v %v", fi, err)
	}
}
