//go:build linux

package hook

import (
	"io"
	"strings"
	"testing"
	"time"
)

// The copy gatekeeper keeps is complete whenever the stdin ends within the cap,
// whether the upstream read all of it, part of it, or none.
func TestRunComposedCopyIsCompleteWhateverTheUpstreamReads(t *testing.T) {
	payload := strings.Repeat(`{"tool_name":"Bash"}`, 5000)
	for name, script := range map[string]string{
		"reads nothing": "exit 0",
		"reads a bit":   "head -c 3 > /dev/null\nexit 0",
		"reads all":     "cat > /dev/null\nexit 0",
	} {
		raw, _, upErr, readErr := RunComposed(rawScript(t, script), strings.NewReader(payload), 20*time.Second)
		if upErr != nil || readErr != nil {
			t.Fatalf("%s: %v %v", name, upErr, readErr)
		}
		if string(raw) != payload {
			t.Errorf("%s: copy is %d bytes, want %d", name, len(raw), len(payload))
		}
	}
}

// A stdin that never ends costs a bounded wait and gives no copy.
func TestRunComposedDrainIsBounded(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("{")) }()
	start := time.Now()
	raw, _, upErr, _ := RunComposed(rawScript(t, "exit 0"), pr, 20*time.Second)
	if upErr != nil || raw != nil {
		t.Fatalf("raw %q, upErr %v", raw, upErr)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %s", d)
	}
}
