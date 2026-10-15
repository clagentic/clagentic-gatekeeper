//go:build linux

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// A delivery directory whose path carries a shell metacharacter is never placed
// in a statement: the call proceeds unchanged and the refusal is logged.
func TestUnsafeDeliveryDirIsNotDelivered(t *testing.T) {
	for _, name := range []string{"has space", "semi;colon", "dollar$x", "back`tick", "quo'te", "brace{a,b}", "glob*"} {
		h := newHarness(t, ModeEnforce)
		startSession(t, h, "")
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, identity.DeliveryFile), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		rec, ok, err := h.hook.Store.Get(testSession, "")
		if err != nil || !ok {
			t.Fatalf("no session record: %v", err)
		}
		rec.Dir = dir
		if err := h.hook.Store.Put(testSession, "", rec); err != nil {
			t.Fatal(err)
		}
		res := h.fire(EventPreToolUseBash, bashPayload("", "", programCommand))
		if len(res.Stdout) != 0 || res.ExitCode != 0 {
			t.Errorf("%q: delivered or failed: stdout %q exit %d", name, res.Stdout, res.ExitCode)
		}
		if !strings.Contains(h.log(), "not a plain absolute path") {
			t.Errorf("%q: the refusal was not logged: %q", name, h.log())
		}
	}
}
