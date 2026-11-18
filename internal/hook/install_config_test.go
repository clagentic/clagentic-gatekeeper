package hook

import (
	"strings"
	"testing"
	"time"
)

// A registration that names a config lets user-prompt-submit read the
// turn-origin provider from it, and gives that one hook the time the provider
// may take. No other hook changes.
func TestInstallConfigReachesOnlyUserPromptSubmit(t *testing.T) {
	in := testInstall(t)
	plain := map[string]int{}
	for _, ev := range Events {
		plain[ev] = in.timeoutFor(ev)
		if strings.Contains(in.Command(ev), "--config") {
			t.Errorf("%s: --config without a config", ev)
		}
	}
	in.Config = "/etc/example/gatekeeper.yaml"
	for _, ev := range Events {
		wantFlag := ev == EventUserPromptSubmit
		if got := strings.Contains(in.Command(ev), "--config /etc/example/gatekeeper.yaml"); got != wantFlag {
			t.Errorf("%s: --config present = %v, want %v", ev, got, wantFlag)
		}
		want := plain[ev]
		if wantFlag {
			want += int(MaxProviderTimeout / time.Second)
		}
		if got := in.timeoutFor(ev); got != want {
			t.Errorf("%s: timeout %d, want %d", ev, got, want)
		}
	}
	in.Config = "relative.yaml"
	if err := in.Validate(); err == nil {
		t.Error("a relative --config was accepted")
	}
}
