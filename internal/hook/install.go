package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// gives up sooner. For the composed pre-tool-use-bash entry it is the budget
	// the composed hook gets, the timeout it had when registered alone, and the
	// entry's own runtime timeout is that plus composeAllowanceSeconds.
	TimeoutSeconds int
}

// composeAllowanceSeconds is the time the runtime gives the composed entry on
// top of the upstream's budget: room for this hook's own issuer call and its
// watchdog, so the runtime never cuts the hook off while the upstream is still
// within its budget or before the upstream's verdict can be emitted.
const composeAllowanceSeconds = 8

// timeoutFor is the runtime-side timeout registered for event.
func (in Install) timeoutFor(event string) int {
	if event == EventPreToolUseBash && in.Compose != "" {
		return in.TimeoutSeconds + composeAllowanceSeconds
	}
	return in.TimeoutSeconds
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
		return ErrOriginHuman
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
			parts = append(parts, "--compose", shellQuote(in.Compose),
				"--upstream-timeout", strconv.Itoa(in.TimeoutSeconds)+"s")
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
		timeout := json.Number(strconv.Itoa(in.timeoutFor(r.event)))
		keptGroups := make([]any, 0, len(groups))
		for _, group := range groups {
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
				if got, _ := e["timeout"].(json.Number); got != timeout {
					e["timeout"] = timeout
					changed = true
				}
				kept = append(kept, e)
			}
			if len(kept) != len(entries) {
				g["hooks"] = kept
			}
			// A group that dropping a duplicate emptied would stay behind as a
			// matcher with nothing to run.
			if g != nil && len(entries) > 0 && len(kept) == 0 {
				continue
			}
			keptGroups = append(keptGroups, group)
		}
		groups = keptGroups
		if !found {
			group := map[string]any{"hooks": []any{map[string]any{
				"type": "command", "command": want, "timeout": timeout,
			}}}
			if r.matcher != "" {
				group["matcher"] = r.matcher
			}
			groups = append(groups, group)
			changed = true
		}
		h[r.runtime] = groups
	}
	ruleAdded, err := addAllowRule(root)
	if err != nil {
		return false, err
	}
	return changed || ruleAdded, nil
}

// Remove unregisters every entry of this adapter and reports whether root
// changed. Groups it empties are dropped; nothing else is touched.
func Remove(root settings) (bool, error) {
	ruleRemoved, err := removeAllowRule(root)
	if err != nil {
		return false, err
	}
	h, err := hooksOf(root, false)
	if err != nil || h == nil {
		return ruleRemoved, err
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
	// A hooks object this removal emptied is dropped with it.
	if changed && len(h) == 0 {
		delete(root, "hooks")
	}
	return changed || ruleRemoved, nil
}

// ApplySettingsFile edits the settings file at path. remove selects
// unregistration instead of registration. When nothing would change the file is
// not touched. With dryRun the new content is returned and nothing is written.
func ApplySettingsFile(path string, in *Install, remove, dryRun bool) (changed bool, content []byte, err error) {
	target, err := resolveTarget(path)
	if err != nil {
		return false, nil, err
	}
	var existing os.FileInfo
	root := settings{}
	raw, err := os.ReadFile(target)
	switch {
	case err == nil:
		if existing, err = os.Stat(target); err != nil {
			return false, nil, err
		}
		if root, err = decodeSettings(raw); err != nil {
			return false, nil, fmt.Errorf("%s: %w", path, err)
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
	return true, content, writeAtomic(target, content, existing)
}

// maxLinkHops bounds how many symbolic links resolveTarget follows.
const maxLinkHops = 40

// resolveTarget follows symbolic links at the final component of path to the
// file that is really edited, including a link whose target does not exist yet:
// the file is then created at the target, and the link stays a link.
func resolveTarget(path string) (string, error) {
	p := path
	for hops := 0; hops < maxLinkHops; hops++ {
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			return p, nil
		}
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return p, nil
		}
		dest, err := os.Readlink(p)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(filepath.Dir(p), dest)
		}
		p = dest
	}
	return "", fmt.Errorf("%s: too many levels of symbolic links", path)
}

// decodeSettings parses exactly one JSON object. null, any other value, an
// empty input and anything after the object, valid JSON or not, are refused.
func decodeSettings(raw []byte) (settings, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root settings
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if root == nil {
		return nil, errors.New("not a JSON object: the value is null")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("has content after the JSON object")
	}
	return root, nil
}

// writeAtomic replaces the file at path with content. The new content is
// written to a temporary file in the same directory, given the owner and mode of
// the file it replaces, and flushed to disk before the rename makes it visible;
// the directory is flushed after, so a crash leaves the old file or the new
// one and never a truncated one. existing is nil for a file being created.
func writeAtomic(path string, content []byte, existing os.FileInfo) error {
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
	mode := os.FileMode(0o600)
	if existing != nil {
		mode = existing.Mode().Perm()
		if err := chownLike(tmp, existing); err != nil {
			return fail(fmt.Errorf("keep the owner of %s: %w", path, err))
		}
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
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
	return syncDir(filepath.Dir(path))
}
