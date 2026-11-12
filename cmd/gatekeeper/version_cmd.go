package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
)

// buildCommit is set at link time (-ldflags "-X main.buildCommit=<sha>", which
// `make install COMMIT=<sha>` passes). It carries the commit when Go's own VCS
// stamping yields nothing, for example a build tree without usable git data.
var buildCommit string

// Where the reported commit came from.
const (
	commitSourceBuildFlag = "build_flag"
	commitSourceVCS       = "vcs"
	commitSourceNone      = "none"
)

// buildVersion is what `gatekeeper version` reports about the source the binary
// was built from. Commit is nil when the build carried neither a build-flag
// commit nor VCS data; nothing is guessed in its place, so a reader can tell
// "unknown" from a real commit. Dirty and VCSTime come from VCS data only and
// are nil when only the build flag supplied the commit. VCSRevision is the
// revision Go stamped, shown next to a build-flag commit so a mismatch is
// visible.
type buildVersion struct {
	Commit       *string `json:"commit"`
	CommitSource string  `json:"commit_source"`
	VCSRevision  *string `json:"vcs_revision"`
	Dirty        *bool   `json:"dirty"`
	GoVersion    string  `json:"go_version"`
	VCSTime      *string `json:"vcs_time"`
}

// versionFromBuildInfo combines the link-time commit with the vcs.* settings
// the Go toolchain stamps into a binary. It takes both as input so every shape
// is testable without building a binary.
func versionFromBuildInfo(settings []debug.BuildSetting, goVersion, flagCommit string) buildVersion {
	v := buildVersion{GoVersion: goVersion}
	for _, s := range settings {
		val := s.Value
		switch s.Key {
		case "vcs.revision":
			if val != "" {
				v.VCSRevision = &val
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
	// A dirty flag or time without a revision describes nothing a reader can act on.
	if v.VCSRevision == nil {
		v.Dirty = nil
		v.VCSTime = nil
	}
	switch {
	case flagCommit != "":
		v.Commit = &flagCommit
		v.CommitSource = commitSourceBuildFlag
	case v.VCSRevision != nil:
		rev := *v.VCSRevision
		v.Commit = &rev
		v.CommitSource = commitSourceVCS
		// The revision is the commit here; repeating it would be noise.
		v.VCSRevision = nil
	default:
		v.CommitSource = commitSourceNone
	}
	return v
}

// text is the human form:
// "clagentic-gatekeeper <commit> dirty=<bool|unknown> commit_source=<source>",
// with " vcs_revision=<rev>" appended when a build-flag commit and a Go-stamped
// revision are both present, or "clagentic-gatekeeper commit unknown" when the
// build had neither.
func (v buildVersion) text() string {
	if v.Commit == nil {
		return "clagentic-gatekeeper commit unknown"
	}
	dirty := "unknown"
	if v.Dirty != nil {
		dirty = fmt.Sprintf("%t", *v.Dirty)
	}
	s := fmt.Sprintf("clagentic-gatekeeper %s dirty=%s commit_source=%s", *v.Commit, dirty, v.CommitSource)
	if v.VCSRevision != nil {
		s += " vcs_revision=" + *v.VCSRevision
	}
	return s
}

// runVersion prints the build's source commit. read is debug.ReadBuildInfo in
// the binary; a failed read is treated as a build with no VCS data. flagCommit
// is the link-time buildCommit.
func runVersion(args []string, read func() (*debug.BuildInfo, bool), flagCommit string, out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOutput := fs.Bool("json", false, "emit {commit, commit_source, vcs_revision, dirty, go_version, vcs_time} JSON; commit is null when the build had no commit data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var settings []debug.BuildSetting
	goVersion := ""
	if info, ok := read(); ok && info != nil {
		settings, goVersion = info.Settings, info.GoVersion
	}
	v := versionFromBuildInfo(settings, goVersion, flagCommit)
	if *jsonOutput {
		return json.NewEncoder(out).Encode(v)
	}
	_, err := fmt.Fprintln(out, v.text())
	return err
}
