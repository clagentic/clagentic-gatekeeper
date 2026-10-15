package hook

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestHelperExitOne is the child of exitedOne: a process that exits 1 on every
// GOOS, which is also the code Windows reports for a process it terminated.
func TestHelperExitOne(t *testing.T) {
	if os.Getenv("GATEKEEPER_TEST_HELPER_EXIT") == "1" {
		os.Exit(1)
	}
}

func exitedOne(t *testing.T) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperExitOne$")
	cmd.Env = append(os.Environ(), "GATEKEEPER_TEST_HELPER_EXIT=1")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("helper did not exit 1: %v", err)
	}
	return err
}

// On Windows a process killed at the deadline reports a non-negative exit code,
// indistinguishable from a verdict by the code alone. A process this package
// killed has no verdict whatever code it reports; one that exited by itself keeps
// its code, a deadline-racing exit included.
func TestKilledUpstreamHasNoVerdictWhateverItsExitCode(t *testing.T) {
	runErr := exitedOne(t)
	if _, err := classifyUpstream(Result{Stdout: []byte("partial")}, runErr, true, true); err == nil {
		t.Fatal("a process killed at the deadline gave a verdict")
	}
	got, err := classifyUpstream(Result{Stdout: []byte("v")}, runErr, true, false)
	if err != nil || got.ExitCode != 1 || string(got.Stdout) != "v" {
		t.Fatalf("an exit at the deadline lost its verdict: %+v %v", got, err)
	}
}

func TestCapturedStdinKeepsABoundedCopyAndPassesEverythingThrough(t *testing.T) {
	c := &capturedStdin{r: strings.NewReader(strings.Repeat("x", 100)), limit: 10}
	n, err := io.Copy(io.Discard, c)
	if err != nil || n != 100 {
		t.Fatalf("passed %d bytes: %v", n, err)
	}
	if c.buf.Len() != 10 || !c.eof || c.err != nil {
		t.Fatalf("copy %d eof %v err %v", c.buf.Len(), c.eof, c.err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestCapturedStdinReadErrorEndsTheStreamAndIsRecorded(t *testing.T) {
	c := &capturedStdin{r: failingReader{}, limit: 10}
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("the upstream saw an error: %v", err)
	}
	if c.eof || c.err == nil {
		t.Fatalf("eof %v err %v", c.eof, c.err)
	}
}
