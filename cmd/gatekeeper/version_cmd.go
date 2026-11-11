package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
)

// buildVersion is what `gatekeeper version` reports about the source the binary
// was built from. Commit and Dirty are nil when the build carried no VCS data
// (a build outside a checkout, or with -buildvcs=false); nothing is guessed in
// their place, so a reader can tell "unknown" from a real commit.
type buildVersion struct {
	Commit    *string `json:"commit"`
	Dirty     *bool   `json:"dirty"`
	GoVersion string  `json:"go_version"`
	VCSTime   *string `json:"vcs_time"`
}

// versionFromBuildInfo reads the vcs.* settings the Go toolchain stamps into a
// binary. It takes the settings as input so the clean, dirty and no-VCS shapes
// are testable without building a binary.
func versionFromBuildInfo(settings []debug.BuildSetting, goVersion string) buildVersion {
	v := buildVersion{GoVersion: goVersion}
	for _, s := range settings {
		val := s.Value
		switch s.Key {
		case "vcs.revision":
			if val != "" {
				v.Commit = &val
			}
		case "vcs.modified":
			switch val {
			case "true":
				d := true
				v.Dirty = &d
			case "false":
				d := false
				v.Dirty = &d
			}
		case "vcs.time":
			if val != "" {
				v.VCSTime = &val
			}
		}
	}
	// A dirty flag without a revision describes nothing a reader can act on.
	if v.Commit == nil {
		v.Dirty = nil
		v.VCSTime = nil
	}
	return v
}

// text is the human form: "clagentic-gatekeeper <commit> dirty=<bool>", or
// "clagentic-gatekeeper commit unknown" when the build had no VCS data.
func (v buildVersion) text() string {
	if v.Commit == nil {
		return "clagentic-gatekeeper commit unknown"
	}
	dirty := "unknown"
	if v.Dirty != nil {
		dirty = fmt.Sprintf("%t", *v.Dirty)
	}
	return fmt.Sprintf("clagentic-gatekeeper %s dirty=%s", *v.Commit, dirty)
}

// runVersion prints the build's source commit. read is debug.ReadBuildInfo in
// the binary; a failed read is treated as a build with no VCS data.
func runVersion(args []string, read func() (*debug.BuildInfo, bool), out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOutput := fs.Bool("json", false, "emit {commit, dirty, go_version, vcs_time} JSON; commit and dirty are null when the build had no VCS data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var v buildVersion
	if info, ok := read(); ok && info != nil {
		v = versionFromBuildInfo(info.Settings, info.GoVersion)
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(v)
	}
	_, err := fmt.Fprintln(out, v.text())
	return err
}
