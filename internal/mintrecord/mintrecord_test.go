package mintrecord

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprintIsA16CharHashPrefix(t *testing.T) {
	// sha256("abc") starts ba7816bf8f01cfea.
	if got := Fingerprint("abc"); got != "ba7816bf8f01cfea" {
		t.Errorf("Fingerprint(abc) = %q", got)
	}
}

func TestSinkOffWritesNothing(t *testing.T) {
	if err := (Sink{}).Write(Record{Role: "r", Outcome: OutcomeOK}); err != nil {
		t.Fatalf("Write on an off sink: %v", err)
	}
}

func TestSinkAppendsOneLinePerRecordWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mints.jsonl")
	s := Sink{Path: path}
	for _, role := range []string{"one", "two"} {
		if err := s.Write(Record{Role: role, Outcome: OutcomeOK}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"role":"one"`) || !strings.Contains(lines[1], `"role":"two"`) {
		t.Errorf("lines = %q", lines)
	}
	if !strings.Contains(lines[0], `"requested_repositories":[]`) {
		t.Errorf("no repositories must encode as [], got %s", lines[0])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSinkUnwritablePathReportsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "mints.jsonl")
	err := Sink{Path: path}.Write(Record{Outcome: OutcomeOK})
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want one naming %s", err, path)
	}
}
