package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// maxLogBytes bounds each log file; on overflow the file is moved to <name>.1,
// replacing the previous overflow.
const maxLogBytes = 1 << 20

// Log appends diagnostic lines. It never fails a hook: an unwritable log is
// silent, because a hook must not turn a logging problem into a blocked tool call.
type Log struct {
	Path string
	Now  func() time.Time
}

func appendBounded(path string, line []byte) {
	if path == "" {
		return
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// Printf records one line with a timestamp. Callers pass no token or payload
// value; only ids, event names and error causes.
func (l Log) Printf(format string, args ...any) {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	appendBounded(l.Path, []byte(now().UTC().Format(time.RFC3339)+" "+fmt.Sprintf(format, args...)+"\n"))
}

// Capture records the shape of events: which members arrived and of which JSON
// type, never a value. It exists so a registration can run in warn mode and
// show which payload shapes and process trees really occur before delivery is
// enforced.
type Capture struct {
	Path string
	Now  func() time.Time
}

// CaptureEntry is one captured event.
type CaptureEntry struct {
	Time      string            `json:"time"`
	Event     string            `json:"event"`
	Decision  string            `json:"decision"`
	Members   map[string]string `json:"members"`
	ToolInput map[string]string `json:"tool_input,omitempty"`
	// Ancestry lists the hook process and its parents, nearest first.
	Ancestry []ProcNode `json:"ancestry,omitempty"`
}

// Shape maps each member name to its JSON type.
func Shape(m map[string]json.RawMessage) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = jsonType(v)
	}
	return out
}

func jsonType(raw json.RawMessage) string {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return "object"
		case '[':
			return "array"
		case '"':
			return "string"
		case 't', 'f':
			return "boolean"
		case 'n':
			return "null"
		default:
			return "number"
		}
	}
	return "empty"
}

// Record appends the entry for p.
func (c Capture) Record(event string, p Payload, decision string, ancestry []ProcNode) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	e := CaptureEntry{
		Time: now().UTC().Format(time.RFC3339), Event: event, Decision: decision,
		Members: Shape(p.Raw), ToolInput: Shape(p.ToolInput), Ancestry: ancestry,
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	appendBounded(c.Path, append(line, '\n'))
}

// MemberNames returns the sorted member names of a shape, for stable assertions.
func MemberNames(shape map[string]string) []string {
	names := make([]string, 0, len(shape))
	for k := range shape {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
