package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Install describes the registration of the Claude Code hooks.
type Install struct {
	// Binary is the absolute path of the gatekeeper binary the hooks run.
	Binary string
	// Socket is the issuer socket; it is always written into the command, so a
	// registered hook never falls back to a default.
	Socket   string
	StateDir string
	Mode     Mode
	Origin   string
	// RefreshBelow is passed to user-prompt-submit when positive.
	RefreshBelow time.Duration
	// Compose is passed to pre-tool-use-bash when set.
	Compose string
	// TimeoutSeconds is the runtime-side timeout of every hook; the hook itself
	// gives up sooner.
	TimeoutSeconds int
}

// registration maps each event to the runtime's event name and matcher.
var registrations = []struct {
	event   string
	runtime string
	matcher string
}{
	{EventSessionStart, "SessionStart", ""},
	{EventUserPromptSubmit, "UserPromptSubmit", ""},
	{EventSubagentStart, "SubagentStart", ""},
	{EventPreToolUseBash, "PreToolUse", "Bash"},
	{EventSubagentStop, "SubagentStop", ""},
}

var plainArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(s string) string {
	if plainArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Validate refuses an incomplete registration.
func (in Install) Validate() error {
	switch {
	case !filepath.IsAbs(in.Binary):
		return errors.New("--binary must be an absolute path")
	case in.Socket == "" || !filepath.IsAbs(in.Socket):
		return errors.New("--socket must be an absolute path: a registered hook never uses a default socket")
	case !filepath.IsAbs(in.StateDir):
		return errors.New("--state-dir must be an absolute path")
	case in.Compose != "" && !filepath.IsAbs(in.Compose):
		return errors.New("--compose must be an absolute path")
	case in.Origin == "human":
		return errors.New("origin human is never requested by the adapter")
	}
	if _, err := ParseMode(string(in.Mode)); err != nil {
		return err
	}
	if in.TimeoutSeconds <= 0 {
		return errors.New("the hook timeout must be positive")
	}
	return nil
}

// Command returns the command line registered for event.
func (in Install) Command(event string) string {
	parts := []string{shellQuote(in.Binary), "hook", "claude-code", event,
		"--socket", shellQuote(in.Socket), "--state-dir", shellQuote(in.StateDir), "--mode", string(in.Mode)}
	if in.Origin != "" {
		parts = append(parts, "--origin", shellQuote(in.Origin))
	}
	switch event {
	case EventUserPromptSubmit:
		if in.RefreshBelow > 0 {
			parts = append(parts, "--refresh-below", in.RefreshBelow.String())
		}
	case EventPreToolUseBash:
		if in.Compose != "" {
			parts = append(parts, "--compose", shellQuote(in.Compose))
		}
	}
	return strings.Join(parts, " ")
}

// ours reports whether command is a registration of this adapter for event.
func ours(command, event string) bool {
	marker := " hook claude-code " + event
	i := strings.Index(command, marker)
	if i < 0 {
		return false
	}
	rest := command[i+len(marker):]
	return rest == "" || rest[0] == ' '
}

func anyOurs(command string) bool {
	for _, r := range registrations {
		if ours(command, r.event) {
			return true
		}
	}
	return false
}

type settings = map[string]any

func hooksOf(root settings, create bool) (settings, error) {
	raw, ok := root["hooks"]
	if !ok {
		if !create {
			return nil, nil
		}
		h := settings{}
		root["hooks"] = h
		return h, nil
	}
	h, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New(`settings "hooks" is not an object`)
	}
	return h, nil
}

func groupsOf(h settings, name string) ([]any, error) {
	raw, ok := h[name]
	if !ok {
		return nil, nil
	}
	groups, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("settings hooks.%s is not an array", name)
	}
	return groups, nil
}

// entriesOf returns the hook entries of a group.
func entriesOf(group any) (map[string]any, []any) {
	g, ok := group.(map[string]any)
	if !ok {
		return nil, nil
	}
	entries, _ := g["hooks"].([]any)
	return g, entries
}

func entryCommand(entry any) (map[string]any, string) {
	e, ok := entry.(map[string]any)
	if !ok {
		return nil, ""
	}
	cmd, _ := e["command"].(string)
	return e, cmd
}

// Apply registers the hooks in root and reports whether root changed. It adds
// its own group for each event and never edits a group or entry it did not
// create; an entry of its own whose command differs (a changed mode, for
// example) is updated in place. Applying it twice changes nothing the second time.
func (in Install) Apply(root settings) (bool, error) {
	if err := in.Validate(); err != nil {
		return false, err
	}
	h, err := hooksOf(root, true)
	if err != nil {
		return false, err
	}
	changed := false
	for _, r := range registrations {
		want := in.Command(r.event)
		groups, err := groupsOf(h, r.runtime)
		if err != nil {
			return false, err
		}
		found := false
		for gi, group := range groups {
			g, entries := entriesOf(group)
			kept := make([]any, 0, len(entries))
			for _, entry := range entries {
				e, cmd := entryCommand(entry)
				if e == nil || !ours(cmd, r.event) {
					kept = append(kept, entry)
					continue
				}
				if found {
					changed = true // a duplicate registration is dropped
					continue
				}
				found = true
				if cmd != want {
					e["command"] = want
					changed = true
				}
				if got, _ := e["timeout"].(json.Number); got.String() != strconv.Itoa(in.TimeoutSeconds) {
					e["timeout"] = json.Number(strconv.Itoa(in.TimeoutSeconds))
					changed = true
				}
				kept = append(kept, e)
			}
			if len(kept) != len(entries) {
				g["hooks"] = kept
				groups[gi] = g
			}
		}
		if !found {
			group := map[string]any{"hooks": []any{map[string]any{
				"type": "command", "command": want, "timeout": json.Number(strconv.Itoa(in.TimeoutSeconds)),
			}}}
			if r.matcher != "" {
				group["matcher"] = r.matcher
			}
			groups = append(groups, group)
			changed = true
		}
		h[r.runtime] = groups
	}
	return changed, nil
}

// Remove unregisters every entry of this adapter and reports whether root
// changed. Groups it empties are dropped; nothing else is touched.
func Remove(root settings) (bool, error) {
	h, err := hooksOf(root, false)
	if err != nil || h == nil {
		return false, err
	}
	changed := false
	for _, r := range registrations {
		groups, err := groupsOf(h, r.runtime)
		if err != nil {
			return false, err
		}
		var keptGroups []any
		for _, group := range groups {
			g, entries := entriesOf(group)
			var kept []any
			for _, entry := range entries {
				if _, cmd := entryCommand(entry); anyOurs(cmd) {
					changed = true
					continue
				}
				kept = append(kept, entry)
			}
			if g != nil && len(kept) == 0 && len(entries) > 0 {
				continue
			}
			if g != nil && len(kept) != len(entries) {
				g["hooks"] = kept
			}
			keptGroups = append(keptGroups, group)
		}
		if _, present := h[r.runtime]; !present {
			continue
		}
		if len(keptGroups) == 0 && len(groups) > 0 {
			delete(h, r.runtime)
		} else if len(keptGroups) != len(groups) {
			h[r.runtime] = keptGroups
		}
	}
	return changed, nil
}

// ApplySettingsFile edits the settings file at path. remove selects
// unregistration instead of registration. When nothing would change the file is
// not touched. With dryRun the new content is returned and nothing is written.
func ApplySettingsFile(path string, in *Install, remove, dryRun bool) (changed bool, content []byte, err error) {
	target := path
	if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
		target = resolved
	}
	mode := os.FileMode(0o600)
	root := settings{}
	raw, err := os.ReadFile(target)
	switch {
	case err == nil:
		if fi, serr := os.Stat(target); serr == nil {
			mode = fi.Mode().Perm()
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&root); err != nil {
			return false, nil, fmt.Errorf("%s is not a JSON object: %w", path, err)
		}
		if _, err := dec.Token(); err == nil {
			return false, nil, fmt.Errorf("%s has content after the JSON object", path)
		}
	case errors.Is(err, os.ErrNotExist):
		if remove {
			return false, nil, nil
		}
	default:
		return false, nil, err
	}
	if remove {
		changed, err = Remove(root)
	} else {
		changed, err = in.Apply(root)
	}
	if err != nil || !changed {
		return false, nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return false, nil, err
	}
	content = buf.Bytes()
	if dryRun {
		return true, content, nil
	}
	return true, content, writeAtomic(target, content, mode)
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
