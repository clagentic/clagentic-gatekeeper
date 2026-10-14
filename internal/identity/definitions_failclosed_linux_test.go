package identity

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const defsProbeEnv = "IDENTITY_TEST_DEFS_PROBE_DIR"

// TestDefinitionsProbeProcess is the body of a child that only opens a
// definitions directory. It is a no-op in a normal test run.
func TestDefinitionsProbeProcess(t *testing.T) {
	dir := os.Getenv(defsProbeEnv)
	if dir == "" {
		t.Skip("probe process only")
	}
	d, err := NewDefinitions(dir)
	if err != nil {
		os.Stdout.WriteString("refused: " + err.Error() + "\n")
		return
	}
	d.Close()
	os.Stdout.WriteString("started\n")
}

// A regular definition the serving uid cannot open cannot be checked, so start
// refuses and names it instead of serving with an unverified roster.
func TestUnreadableRegularDefinitionRefusesStartNamingFile(t *testing.T) {
	dir := shortSocketDir(t)
	writeDefinition(t, dir, "example-ok", "builder")
	writeDefinition(t, dir, "example-sealed", "merger")
	if err := os.Chmod(filepath.Join(dir, "example-sealed.md"), 0); err != nil {
		t.Fatal(err)
	}

	var out string
	if os.Geteuid() != 0 {
		_, err := NewDefinitions(dir)
		if err == nil {
			t.Fatal("start accepted a definition it cannot open")
		}
		out = "refused: " + err.Error()
	} else {
		// Root opens any file, so the check has to run under a non-root uid.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		self, err := os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "probe.test")
		if err := os.WriteFile(bin, self, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-test.run=^TestDefinitionsProbeProcess$")
		cmd.Env = append(os.Environ(), defsProbeEnv+"="+dir)
		runAsUID(cmd, 65534)
		raw, err := cmd.Output()
		if err != nil {
			t.Skipf("cannot run a probe as a non-root uid: %v", err)
		}
		out = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	}
	if !strings.HasPrefix(out, "refused") || !strings.Contains(out, "example-sealed.md") {
		t.Fatalf("got %q, want a refusal naming example-sealed.md", out)
	}
}

// The one documented skip: an entry that is not a regular file does not stop
// start, and is refused when named.
func TestNonRegularEntriesAreSkippedAtStart(t *testing.T) {
	dir := t.TempDir()
	writeDefinition(t, dir, "example-ok", "builder")
	if err := os.Mkdir(filepath.Join(dir, "example-dir.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "example-fifo.md"), 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "example-ok.md"), filepath.Join(dir, "example-link.md")); err != nil {
		t.Fatal(err)
	}
	d := newDefs(t, dir)
	if _, err := d.Load("example-ok"); err != nil {
		t.Fatal(err)
	}
}
