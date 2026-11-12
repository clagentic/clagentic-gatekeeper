package main

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"testing"
)

func TestVersionFormatting(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	const flagSHA = "fedcba9876543210fedcba9876543210fedcba98"
	cases := []struct {
		name       string
		settings   []debug.BuildSetting
		flagCommit string
		text       string
		commit     any
		source     string
		vcsRev     any
		dirty      any
		vcsTime    any
	}{
		{
			name:     "clean vcs build",
			settings: []debug.BuildSetting{{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "false"}, {Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}},
			text:     "clagentic-gatekeeper " + sha + " dirty=false commit_source=vcs",
			commit:   sha, source: "vcs", vcsRev: nil, dirty: false, vcsTime: "2026-01-02T03:04:05Z",
		},
		{
			name:     "dirty vcs build",
			settings: []debug.BuildSetting{{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}},
			text:     "clagentic-gatekeeper " + sha + " dirty=true commit_source=vcs",
			commit:   sha, source: "vcs", vcsRev: nil, dirty: true, vcsTime: nil,
		},
		{
			name:       "build flag only",
			settings:   []debug.BuildSetting{{Key: "-compiler", Value: "gc"}},
			flagCommit: flagSHA,
			text:       "clagentic-gatekeeper " + flagSHA + " dirty=unknown commit_source=build_flag",
			commit:     flagSHA, source: "build_flag", vcsRev: nil, dirty: nil, vcsTime: nil,
		},
		{
			name:       "build flag wins and vcs revision is shown",
			settings:   []debug.BuildSetting{{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}, {Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}},
			flagCommit: flagSHA,
			text:       "clagentic-gatekeeper " + flagSHA + " dirty=true commit_source=build_flag vcs_revision=" + sha,
			commit:     flagSHA, source: "build_flag", vcsRev: sha, dirty: true, vcsTime: "2026-01-02T03:04:05Z",
		},
		{
			name:     "no vcs settings",
			settings: []debug.BuildSetting{{Key: "-compiler", Value: "gc"}},
			text:     "clagentic-gatekeeper commit unknown",
			commit:   nil, source: "none", vcsRev: nil, dirty: nil, vcsTime: nil,
		},
		{
			name:     "modified without revision stays unknown",
			settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}},
			text:     "clagentic-gatekeeper commit unknown",
			commit:   nil, source: "none", vcsRev: nil, dirty: nil, vcsTime: nil,
		},
		{
			name:       "modified without revision under a build flag has no dirty",
			settings:   []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}},
			flagCommit: flagSHA,
			text:       "clagentic-gatekeeper " + flagSHA + " dirty=unknown commit_source=build_flag",
			commit:     flagSHA, source: "build_flag", vcsRev: nil, dirty: nil, vcsTime: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read := func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{GoVersion: "go-test", Settings: c.settings}, true
			}

			var text bytes.Buffer
			if err := runVersion(nil, read, c.flagCommit, &text); err != nil {
				t.Fatalf("runVersion: %v", err)
			}
			if got := text.String(); got != c.text+"\n" {
				t.Errorf("text = %q, want %q", got, c.text+"\n")
			}

			var js bytes.Buffer
			if err := runVersion([]string{"--json"}, read, c.flagCommit, &js); err != nil {
				t.Fatalf("runVersion --json: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(js.Bytes(), &got); err != nil {
				t.Fatalf("json: %v", err)
			}
			if got["commit"] != c.commit || got["commit_source"] != c.source || got["vcs_revision"] != c.vcsRev ||
				got["dirty"] != c.dirty || got["vcs_time"] != c.vcsTime || got["go_version"] != "go-test" {
				t.Errorf("json = %v, want commit=%v commit_source=%v vcs_revision=%v dirty=%v vcs_time=%v",
					got, c.commit, c.source, c.vcsRev, c.dirty, c.vcsTime)
			}
		})
	}
}

func TestVersionWithoutBuildInfo(t *testing.T) {
	var out bytes.Buffer
	read := func() (*debug.BuildInfo, bool) { return nil, false }
	if err := runVersion(nil, read, "", &out); err != nil {
		t.Fatalf("runVersion: %v", err)
	}
	if got, want := out.String(), "clagentic-gatekeeper commit unknown\n"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}
