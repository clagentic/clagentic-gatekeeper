package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func allowList(t *testing.T, raw []byte) []any {
	t.Helper()
	perms, _ := decode(t, raw)["permissions"].(map[string]any)
	allow, _ := perms["allow"].([]any)
	return allow
}

func countRule(allow []any) int {
	n := 0
	for _, r := range allow {
		if r == AllowRule {
			n++
		}
	}
	return n
}

func TestAllowRuleIsTheOneExportRule(t *testing.T) {
	if AllowRule != "Bash(export CLAGENTIC_IDENTITY_DIR=*)" {
		t.Fatalf("rule %q", AllowRule)
	}
}

func TestInstallAddsTheAllowRuleOnceNextToTheOthers(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	allow := allowList(t, first)
	if len(allow) != 2 || allow[0] != "Bash(ls:*)" || countRule(allow) != 1 {
		t.Fatalf("allow list %v", allow)
	}
	changed, _, err := ApplySettingsFile(path, &in, false, false)
	if err != nil || changed {
		t.Fatalf("second run: changed=%v err=%v", changed, err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatal("the second run changed the bytes")
	}
}

func TestInstallCreatesPermissionsWhenAbsentAndDoesNotDuplicateAnExistingRule(t *testing.T) {
	in := testInstall(t)
	path := writeSettings(t, `{"theme":"dark"}`)
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if countRule(allowList(t, raw)) != 1 {
		t.Fatalf("%s", raw)
	}
	pre := writeSettings(t, `{"permissions":{"allow":["`+AllowRule+`"],"deny":["Bash(rm:*)"]}}`)
	if _, _, err := ApplySettingsFile(pre, &in, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(pre)
	if countRule(allowList(t, raw)) != 1 || !strings.Contains(string(raw), "Bash(rm:*)") {
		t.Fatalf("%s", raw)
	}
}

// The install tests are single flows, not tables, so the allow-rewritten setting
// has its own flow here: the flag reaches only the pre-tool-use-bash command, no
// export rule is added with it, an existing rule is left alone, turning it off
// restores the entry and the rule in place, and --remove still deletes the rule.
func TestInstallWithAllowRewrittenAddsNoRuleAndRoundTrips(t *testing.T) {
	in := testInstall(t)
	on := in
	on.AllowRewritten = true
	for _, ev := range Events {
		if got := strings.Contains(on.Command(ev), AllowRewrittenFlag); got != (ev == EventPreToolUseBash) {
			t.Errorf("%s: flag present=%v", ev, got)
		}
		if strings.Contains(in.Command(ev), AllowRewrittenFlag) {
			t.Errorf("%s: flag present by default", ev)
		}
	}
	if !strings.HasSuffix(on.Command(EventPreToolUseBash), " "+AllowRewrittenFlag) {
		t.Fatalf("command %q", on.Command(EventPreToolUseBash))
	}

	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &on, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if countRule(allowList(t, raw)) != 0 || strings.Count(string(raw), AllowRewrittenFlag) != 1 {
		t.Fatalf("on-run settings:\n%s", raw)
	}
	if changed, _, err := ApplySettingsFile(path, &on, false, false); err != nil || changed {
		t.Fatalf("second identical run: changed=%v err=%v", changed, err)
	}
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if countRule(allowList(t, raw)) != 1 || strings.Contains(string(raw), AllowRewrittenFlag) {
		t.Fatalf("off-run settings:\n%s", raw)
	}
	if _, _, err := ApplySettingsFile(path, &on, false, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if countRule(allowList(t, raw)) != 1 {
		t.Fatalf("the on-run removed an existing rule:\n%s", raw)
	}
	if _, _, err := ApplySettingsFile(path, nil, true, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), AllowRule) || strings.Contains(string(raw), "claude-code") {
		t.Fatalf("after --remove:\n%s", raw)
	}
}

func TestInstallRefusesMalformedPermissions(t *testing.T) {
	in := testInstall(t)
	for name, body := range map[string]string{
		"permissions not object": `{"permissions":[]}`,
		"allow not array":        `{"permissions":{"allow":"x"}}`,
	} {
		path := writeSettings(t, body)
		if _, _, err := ApplySettingsFile(path, &in, false, false); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if _, _, err := ApplySettingsFile(path, nil, true, false); err == nil {
			t.Errorf("%s was accepted by remove", name)
		}
		if raw, _ := os.ReadFile(path); string(raw) != body {
			t.Errorf("%s: the file was modified", name)
		}
	}
}

func TestRemoveDeletesExactlyTheAllowRule(t *testing.T) {
	in := testInstall(t)
	body := `{"permissions":{"allow":["Bash(ls:*)","Bash(export OTHER=*)","` + AllowRule + `","Bash(export CLAGENTIC_IDENTITY_DIR=/x)"],"deny":["Bash(rm:*)"]}}`
	path := writeSettings(t, body)
	if _, _, err := ApplySettingsFile(path, nil, true, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	allow := allowList(t, raw)
	if len(allow) != 3 || countRule(allow) != 0 {
		t.Fatalf("allow list %v", allow)
	}
	if !strings.Contains(string(raw), "Bash(export CLAGENTIC_IDENTITY_DIR=/x)") || !strings.Contains(string(raw), "Bash(rm:*)") {
		t.Fatalf("a rule other than ours was touched: %s", raw)
	}

	// A register then remove round trip restores the content, including a file
	// that had no permissions at all.
	for _, original := range []string{foreignSettings, `{"theme":"dark"}`, `{}`} {
		p := writeSettings(t, original)
		if _, _, err := ApplySettingsFile(p, &in, false, false); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ApplySettingsFile(p, nil, true, false); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(p)
		var want, have any
		if err := json.Unmarshal([]byte(original), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got, &have); err != nil {
			t.Fatal(err)
		}
		wb, _ := json.Marshal(want)
		hb, _ := json.Marshal(have)
		if !bytes.Equal(wb, hb) {
			t.Errorf("round trip changed the settings\nwant %s\n got %s", wb, hb)
		}
	}
}

// A removal that finds none of our rule changes nothing, so an empty permissions
// object (or one with an empty allow list) a user wrote is left exactly as it was.
func TestRemoveLeavesAnEmptyPermissionsObjectAlone(t *testing.T) {
	for _, body := range []string{`{"permissions":{}}`, `{"permissions":{"allow":[]}}`, `{"permissions":{"deny":[]},"theme":"dark"}`} {
		path := writeSettings(t, body)
		changed, _, err := ApplySettingsFile(path, nil, true, false)
		if err != nil || changed {
			t.Fatalf("%s: changed=%v err=%v", body, changed, err)
		}
		if raw, _ := os.ReadFile(path); string(raw) != body {
			t.Fatalf("%s: the file was rewritten: %s", body, raw)
		}
	}
}

// A settings file that holds only the rule (hooks already removed by hand) is
// still cleaned by remove.
func TestRemoveDeletesTheRuleWhenNoHooksRemain(t *testing.T) {
	path := writeSettings(t, `{"permissions":{"allow":["`+AllowRule+`"]},"hooks":{}}`)
	changed, _, err := ApplySettingsFile(path, nil, true, false)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), AllowRule) {
		t.Fatalf("%s", raw)
	}
}
