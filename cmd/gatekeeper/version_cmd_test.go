package main

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"testing"
)

func TestVersionFormatting(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		text     string
		commit   any
		dirty    any
		vcsTime  any
	}{
		{
			name:     "clean vcs build",
			settings: []debug.BuildSetting{{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "false"}, {Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}},
			text:     "clagentic-gatekeeper " + sha + " dirty=false",
			commit:   sha, dirty: false, vcsTime: "2026-01-02T03:04:05Z",
		},
		{
			name:     "dirty vcs build",
			settings: []debug.BuildSetting{{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}},
			text:     "clagentic-gatekeeper " + sha + " dirty=true",
			commit:   sha, dirty: true, vcsTime: nil,
		},
		{
			name:     "no vcs settings",
			settings: []debug.BuildSetting{{Key: "-compiler", Value: "gc"}},
			text:     "clagentic-gatekeeper commit unknown",
			commit:   nil, dirty: nil, vcsTime: nil,
		},
		{
			name:     "modified without revision stays unknown",
			settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}},
			text:     "clagentic-gatekeeper commit unknown",
			commit:   nil, dirty: nil, vcsTime: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read := func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{GoVersion: "go-test", Settings: c.settings}, true
			}

			var text bytes.Buffer
			if err := runVersion(nil, read, &text); err != nil {
				t.Fatalf("runVersion: %v", err)
			}
			if got := text.String(); got != c.text+"\n" {
				t.Errorf("text = %q, want %q", got, c.text+"\n")
			}

			var js bytes.Buffer
			if err := runVersion([]string{"--json"}, read, &js); err != nil {
				t.Fatalf("runVersion --json: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(js.Bytes(), &got); err != nil {
				t.Fatalf("json: %v", err)
			}
			if got["commit"] != c.commit || got["dirty"] != c.dirty || got["vcs_time"] != c.vcsTime || got["go_version"] != "go-test" {
				t.Errorf("json = %v, want commit=%v dirty=%v vcs_time=%v", got, c.commit, c.dirty, c.vcsTime)
			}
		})
	}
}

func TestVersionWithoutBuildInfo(t *testing.T) {
	var out bytes.Buffer
	read := func() (*debug.BuildInfo, bool) { return nil, false }
	if err := runVersion(nil, read, &out); err != nil {
		t.Fatalf("runVersion: %v", err)
	}
	if got, want := out.String(), "clagentic-gatekeeper commit unknown\n"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}
