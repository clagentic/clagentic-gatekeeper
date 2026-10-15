package hook

import (
	"os"
	"testing"
	"time"
)

// A Store with no root, or a relative one, refuses every call and creates
// nothing under the working directory.
func TestStoreWithoutAnAbsoluteRootIsDisabled(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	for _, root := range []string{"", "state", "./state", "../state"} {
		s := Store{Root: root}
		if _, _, err := s.Get("sess-1", ""); err == nil {
			t.Errorf("%q: Get accepted", root)
		}
		if err := s.Put("sess-1", "", Record{Dir: "/x"}); err == nil {
			t.Errorf("%q: Put accepted", root)
		}
		if _, err := s.PutNew("sess-1", "agent-1", Record{Dir: "/x"}); err == nil {
			t.Errorf("%q: PutNew accepted", root)
		}
		if err := s.Delete("sess-1", ""); err == nil {
			t.Errorf("%q: Delete accepted", root)
		}
		s.Prune(time.Now().Add(100*24*time.Hour), time.Hour)
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatalf("a disabled store touched the working directory: %v %v", entries, err)
	}
}
