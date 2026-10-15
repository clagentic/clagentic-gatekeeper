//go:build linux

package hook

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type zeroes struct{ left int }

func (z *zeroes) Read(p []byte) (int, error) {
	if z.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), z.left)
	clear(p[:n])
	z.left -= n
	return n, nil
}

// rawScript writes an executable whose whole body is script, so it does not read
// stdin unless the script does.
func rawScript(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A payload far over the cap is streamed whole to the upstream while the copy
// gatekeeper keeps stays one byte over the cap, enough to refuse it as too large.
func TestRunComposedStreamsEverythingAndKeepsABoundedCopy(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "bytes")
	exe := rawScript(t, "wc -c > "+seen+"\nprintf v\nexit 2")
	total := 3*maxPayloadBytes + 17
	raw, up, upErr, readErr := RunComposed(exe, &zeroes{left: total}, 20*time.Second)
	if upErr != nil || readErr != nil || up.ExitCode != 2 {
		t.Fatalf("%+v %v %v", up, upErr, readErr)
	}
	if len(raw) != maxPayloadBytes+1 {
		t.Fatalf("gatekeeper kept %d bytes, want %d", len(raw), maxPayloadBytes+1)
	}
	got, err := os.ReadFile(seen)
	if err != nil || strings.TrimSpace(string(got)) != strconv.Itoa(total) {
		t.Fatalf("the upstream read %q (%v), want %d bytes", got, err, total)
	}
	h := newHarness(t, ModeEnforce)
	if res := h.hook.HandleComposed(raw, up, nil); res.ExitCode != 2 || string(res.Stdout) != "v" {
		t.Fatalf("oversized payload did not yield the upstream result: %+v", res)
	}
}

// A stdin the upstream stopped reading is not a payload: nothing is parsed from
// the prefix that was seen.
func TestRunComposedWithAnUnreadStdinGivesNoCopy(t *testing.T) {
	raw, _, upErr, _ := RunComposed(rawScript(t, "exit 0"), &zeroes{left: 64 << 20}, 20*time.Second)
	if upErr != nil || raw != nil {
		t.Fatalf("raw %d bytes, upErr %v", len(raw), upErr)
	}
}
