package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testInstall(t *testing.T) Install {
	t.Helper()
	dir := t.TempDir()
	return Install{
		Binary: "/opt/gk/gatekeeper", Socket: filepath.Join(dir, "id.sock"), StateDir: filepath.Join(dir, "state"),
		Mode: ModeWarn, RefreshBelow: 30 * time.Minute, TimeoutSeconds: 5,
	}
}

const foreignSettings = `{
  "theme": "dark",
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/crew/guard-bash.py"}, {"type": "command", "command": "/opt/crew/inject-spawn-agent-env.py"}]},
      {"matcher": "Write|Edit", "hooks": [{"type": "command", "command": "/opt/crew/guard-scope.py", "timeout": 10}]}
    ],
    "SubagentStop": [{"hooks": [{"type": "command", "command": "/opt/crew/guard-turn-state.py", "timeout": 5}]}],
    "SessionStart": [{"hooks": [{"type": "command", "command": "/opt/lore/session-start.sh"}]}]
  }
}
`

func writeSettings(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallTwiceIsANoOp(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	changed, _, err := ApplySettingsFile(path, &in, false, false)
	if err != nil || !changed {
		t.Fatalf("first run: changed=%v err=%v", changed, err)
	}
	first, _ := os.ReadFile(path)
	fi1, _ := os.Stat(path)
	changed, _, err = ApplySettingsFile(path, &in, false, false)
	if err != nil || changed {
		t.Fatalf("second run: changed=%v err=%v", changed, err)
	}
	second, _ := os.ReadFile(path)
	fi2, _ := os.Stat(path)
	if !bytes.Equal(first, second) || !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("the second run touched the file")
	}
	if fi1.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi1.Mode())
	}
}

func TestInstallKeepsEveryForeignHookAndSetting(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	got := decode(t, raw)
	if got["theme"] != "dark" || got["permissions"] == nil {
		t.Fatalf("settings outside hooks changed: %v", got)
	}
	for _, foreign := range []string{"/opt/crew/guard-bash.py", "/opt/crew/inject-spawn-agent-env.py", "/opt/crew/guard-scope.py", "/opt/crew/guard-turn-state.py", "/opt/lore/session-start.sh"} {
		if !strings.Contains(string(raw), foreign) {
			t.Errorf("%s was lost", foreign)
		}
	}
	hooks := got["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 3 {
		t.Fatalf("PreToolUse groups: %d", len(pre))
	}
	ours := pre[2].(map[string]any)
	if ours["matcher"] != "Bash" {
		t.Fatalf("our group %+v", ours)
	}
	// Our entry shares no group with a foreign hook, so removing it later edits nothing else.
	if n := len(ours["hooks"].([]any)); n != 1 {
		t.Fatalf("our group holds %d hooks", n)
	}
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "SubagentStart", "SubagentStop", "PreToolUse"} {
		if hooks[ev] == nil {
			t.Errorf("no %s registration", ev)
		}
	}
	// The original foreign order is intact ahead of ours.
	first := pre[0].(map[string]any)["hooks"].([]any)
	if first[0].(map[string]any)["command"] != "/opt/crew/guard-bash.py" || first[1].(map[string]any)["command"] != "/opt/crew/inject-spawn-agent-env.py" {
		t.Fatalf("the Bash group was reordered: %v", first)
	}
}

func TestInstalledCommandsAreExplicitAndHaveNoShellWrapper(t *testing.T) {
	in := testInstall(t)
	in.Origin = "agent"
	in.Compose = "/opt/crew/inject-spawn-agent-env.py"
	for _, ev := range Events {
		cmd := in.Command(ev)
		for _, must := range []string{"/opt/gk/gatekeeper hook claude-code " + ev + " ", "--socket " + in.Socket, "--state-dir " + in.StateDir, "--mode warn", "--origin agent"} {
			if !strings.Contains(cmd, must) {
				t.Errorf("%s: %q lacks %q", ev, cmd, must)
			}
		}
		if strings.Contains(cmd, "sh -c") || strings.Contains(cmd, "bash -c") || strings.ContainsAny(cmd, "|&;`$") {
			t.Errorf("%s: shell syntax in %q", ev, cmd)
		}
		if strings.Contains(cmd, "--compose") != (ev == EventPreToolUseBash) {
			t.Errorf("%s: --compose placement in %q", ev, cmd)
		}
		if strings.Contains(cmd, "--refresh-below") != (ev == EventUserPromptSubmit) {
			t.Errorf("%s: --refresh-below placement in %q", ev, cmd)
		}
	}
}

func TestInstallUpdatesItsOwnEntryInPlaceWhenTheModeChanges(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	in.Mode = ModeEnforce
	changed, _, err := ApplySettingsFile(path, &in, false, false)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "--mode warn") || strings.Count(string(raw), "--mode enforce") != 5 {
		t.Fatalf("settings after the mode change:\n%s", raw)
	}
	if strings.Count(string(raw), "hook claude-code pre-tool-use-bash") != 1 {
		t.Fatal("a second pre-tool-use-bash registration was added")
	}
}

func TestInstallCollapsesDuplicateRegistrations(t *testing.T) {
	in := testInstall(t)
	dup := `{"hooks":{"SubagentStop":[{"hooks":[{"type":"command","command":"` + in.Command(EventSubagentStop) + `","timeout":5}]},{"hooks":[{"type":"command","command":"` + in.Command(EventSubagentStop) + `","timeout":5}]}]}}`
	path := writeSettings(t, dup)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "hook claude-code subagent-stop"); n != 1 {
		t.Fatalf("%d subagent-stop registrations:\n%s", n, raw)
	}
}

func TestRemoveRestoresTheForeignSettingsExactly(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	changed, _, err := ApplySettingsFile(path, nil, true, false)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "gatekeeper") {
		t.Fatalf("a registration survived:\n%s", raw)
	}
	var want, got any
	if err := json.Unmarshal([]byte(foreignSettings), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if string(wb) != string(gb) {
		t.Fatalf("remove did not restore the foreign content\nwant %s\n got %s", wb, gb)
	}
	changed, _, err = ApplySettingsFile(path, nil, true, false)
	if err != nil || changed {
		t.Fatalf("second remove: changed=%v err=%v", changed, err)
	}
}

func TestInstallCreatesAMissingSettingsFile(t *testing.T) {
	in := testInstall(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	if changed, _, err := ApplySettingsFile(path, &in, false, false); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if changed, _, err := ApplySettingsFile(filepath.Join(t.TempDir(), "none.json"), nil, true, false); err != nil || changed {
		t.Fatalf("removing from a missing file: changed=%v err=%v", changed, err)
	}
}

func TestInstallDryRunWritesNothing(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	changed, content, err := ApplySettingsFile(path, &in, false, true)
	if err != nil || !changed || !strings.Contains(string(content), "hook claude-code session-start") {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != foreignSettings {
		t.Fatal("a dry run wrote the file")
	}
}

func TestInstallRefusesMalformedAndUnsafeInput(t *testing.T) {
	in := testInstall(t)
	for name, body := range map[string]string{
		"not json":        `hooks: yes`,
		"trailing":        `{} {}`,
		"hooks not obj":   `{"hooks": []}`,
		"event not array": `{"hooks": {"SessionStart": {}}}`,
	} {
		path := writeSettings(t, body)
		if _, _, err := ApplySettingsFile(path, &in, false, false); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if raw, _ := os.ReadFile(path); string(raw) != body {
			t.Errorf("%s: the file was modified", name)
		}
	}
	bad := []Install{
		{Binary: "gatekeeper", Socket: in.Socket, StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 5},
		{Binary: in.Binary, Socket: "", StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 5},
		{Binary: in.Binary, Socket: "rel.sock", StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 5},
		{Binary: in.Binary, Socket: in.Socket, StateDir: "state", Mode: ModeWarn, TimeoutSeconds: 5},
		{Binary: in.Binary, Socket: in.Socket, StateDir: in.StateDir, Mode: "loud", TimeoutSeconds: 5},
		{Binary: in.Binary, Socket: in.Socket, StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 0},
		{Binary: in.Binary, Socket: in.Socket, StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 5, Origin: "human"},
		{Binary: in.Binary, Socket: in.Socket, StateDir: in.StateDir, Mode: ModeWarn, TimeoutSeconds: 5, Compose: "rel"},
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("case %d accepted: %+v", i, b)
		}
	}
}

func TestShellQuoteKeepsAPathWithSpacesOneWord(t *testing.T) {
	if got := shellQuote("/a b/it's"); got != `'/a b/it'\''s'` {
		t.Fatalf("%q", got)
	}
	if got := shellQuote("/plain/path-1.2"); got != "/plain/path-1.2" {
		t.Fatalf("%q", got)
	}
}
