package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func newSpawnDirs(t *testing.T) SpawnDirs {
	t.Helper()
	s := SpawnDirs{Root: filepath.Join(t.TempDir(), "spawn")}
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
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

func TestPublishCreatesFileAndTmpInOrder(t *testing.T) {
	s := newSpawnDirs(t)
	dir, err := s.Create()
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
	dir, err := s.Create()
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
	dir, err := s.Create()
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
	dir, err := s.Create()
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
	dir, err := s.Create()
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

func TestPublishRefusesDirectoryOutsideRoot(t *testing.T) {
	s := newSpawnDirs(t)
	if err := s.Publish(t.TempDir(), selfPeer(1), "tok"); err == nil {
		t.Fatal("publish accepted a directory outside the spawn root")
	}
}
