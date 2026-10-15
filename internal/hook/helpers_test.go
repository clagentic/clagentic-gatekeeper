//go:build linux

package hook

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// fakeIssuer answers issue-session and issue-child over a unix socket and lays
// out real delivery directories, so the hooks are exercised through the real
// client and the real filesystem. It is not the issuer: it grants whatever it is
// asked and checks only that a child names a session it issued.
type fakeIssuer struct {
	t      *testing.T
	Socket string
	root   string

	mu       sync.Mutex
	sessions []identity.SessionRequest
	children []identity.ChildRequest
	tokens   map[string]bool
	seq      int
	// Delay holds every answer back; Fail makes issue-session refuse; TTL is the
	// lifetime in seconds of what it issues.
	Delay time.Duration
	Fail  bool
	TTL   int64
	done  chan struct{}
}

// wait holds an answer back for Delay, or until the test is over.
func (f *fakeIssuer) wait() bool {
	select {
	case <-time.After(f.Delay):
		return true
	case <-f.done:
		return false
	}
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	base, err := os.MkdirTemp("", "gkh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	f := &fakeIssuer{t: t, root: filepath.Join(base, "spawn"), tokens: map[string]bool{}, TTL: 3600, done: make(chan struct{})}
	t.Cleanup(func() { close(f.done) })
	if err := os.Mkdir(f.root, 0o700); err != nil {
		t.Fatal(err)
	}
	f.Socket = filepath.Join(base, "i.sock")
	l, err := net.Listen("unix", f.Socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+identity.PathIssueSession, f.session)
	mux.HandleFunc("POST "+identity.PathIssueChild, f.child)
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeIssuer) answer(w http.ResponseWriter, token string) {
	f.seq++
	dir := filepath.Join(f.root, fmt.Sprintf("%010x-%032x", 0x6000000000+f.seq, f.seq))
	if err := os.Mkdir(dir, 0o700); err != nil {
		f.t.Error(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o700); err != nil {
		f.t.Error(err)
	}
	if err := os.WriteFile(filepath.Join(dir, identity.DeliveryFile), []byte(token+"\n"), 0o600); err != nil {
		f.t.Error(err)
	}
	f.tokens[token] = true
	_ = json.NewEncoder(w).Encode(identity.Issued{Token: token, Dir: dir, ExpiresAt: time.Now().Unix() + f.TTL})
}

func (f *fakeIssuer) session(w http.ResponseWriter, r *http.Request) {
	var req identity.SessionRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !f.wait() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = append(f.sessions, req)
	if f.Fail {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"definition_unknown","message":"the requested definition is not available"}`))
		return
	}
	f.answer(w, fmt.Sprintf("session-token-%d", f.seq+1))
}

func (f *fakeIssuer) child(w http.ResponseWriter, r *http.Request) {
	var req identity.ChildRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !f.wait() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.children = append(f.children, req)
	if !f.tokens[req.ParentToken] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"parent_unknown","message":"the parent token was not recognised"}`))
		return
	}
	f.answer(w, fmt.Sprintf("child-token-%s-%d", req.AgentID, f.seq+1))
}

func (f *fakeIssuer) deliveryDirs() []string {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, filepath.Join(f.root, e.Name()))
	}
	return out
}

// sessionRequests and childRequests return copies taken under the lock, so a
// test never reads what a handler goroutine is still appending to.
func (f *fakeIssuer) sessionRequests() []identity.SessionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]identity.SessionRequest(nil), f.sessions...)
}

func (f *fakeIssuer) childRequests() []identity.ChildRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]identity.ChildRequest(nil), f.children...)
}

func (f *fakeIssuer) counts() (sessions, children int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions), len(f.children)
}

// harness builds a hook handler over the fake issuer.
type harness struct {
	t     *testing.T
	fake  *fakeIssuer
	hook  *ClaudeCode
	state string
}

func newHarness(t *testing.T, mode Mode) *harness {
	t.Helper()
	fake := newFakeIssuer(t)
	state := filepath.Join(t.TempDir(), "state")
	h := &ClaudeCode{
		Issuer:  identity.Client{Socket: fake.Socket, Timeout: 2 * time.Second},
		Store:   Store{Root: state},
		Mode:    mode,
		Log:     Log{Path: filepath.Join(state, "hook.log")},
		Capture: Capture{Path: filepath.Join(state, "shapes.jsonl")},
		HookPID: os.Getpid(),
	}
	return &harness{t: t, fake: fake, hook: h, state: state}
}

// fire sends one event with the given payload members.
func (h *harness) fire(event string, payload map[string]any) Result {
	h.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		// Errorf, not Fatal: fire is also called from goroutines.
		h.t.Errorf("marshal payload: %v", err)
		return Result{}
	}
	return h.hook.Handle(event, strings.NewReader(string(raw)))
}

func (h *harness) log() string {
	raw, _ := os.ReadFile(filepath.Join(h.state, "hook.log"))
	return string(raw)
}

const testSession = "sess-0001"

// programCommand is the command the delivery tests send when the command itself
// does not matter. It runs a program, so it is outside the closed read-only set
// and is always rewritten; a command such as ls would be skipped and make a test
// of any "no delivery" path pass without testing that path.
const programCommand = "make build"

func bashPayload(agentID, agentType, command string) map[string]any {
	p := map[string]any{
		"hook_event_name": "PreToolUse", "session_id": testSession, "tool_name": "Bash",
		"tool_input": map[string]any{"command": command, "timeout": 60000, "run_in_background": false, "description": "d"},
	}
	if agentID != "" {
		p["agent_id"], p["agent_type"] = agentID, agentType
	}
	return p
}

// commandOf extracts updatedInput.command from a hook reply. It reports instead
// of failing, so a goroutine can use it.
func commandOf(res Result) (command string, out map[string]any, err error) {
	if err := json.Unmarshal(res.Stdout, &out); err != nil {
		return "", nil, fmt.Errorf("reply %q: %w", res.Stdout, err)
	}
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("reply %q has no hookSpecificOutput", res.Stdout)
	}
	updated, ok := hso["updatedInput"].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("reply %q has no updatedInput", res.Stdout)
	}
	command, ok = updated["command"].(string)
	if !ok {
		return "", nil, fmt.Errorf("reply %q has no command", res.Stdout)
	}
	return command, out, nil
}

// dirIn extracts the delivery directory from a rewritten command.
func dirIn(command string) (string, error) {
	rest, ok := strings.CutPrefix(command, exportPrefix)
	if !ok {
		return "", fmt.Errorf("command does not start with the delivery statement: %q", command)
	}
	dir, _, ok := strings.Cut(rest, "; ")
	if !ok {
		return "", fmt.Errorf("no statement terminator: %q", command)
	}
	return dir, nil
}

// rewrittenCommand is commandOf for the test goroutine.
func rewrittenCommand(t *testing.T, res Result) (command string, out map[string]any) {
	t.Helper()
	command, out, err := commandOf(res)
	if err != nil {
		t.Fatal(err)
	}
	return command, out
}

// dirOf is dirIn for the test goroutine.
func dirOf(t *testing.T, command string) string {
	t.Helper()
	dir, err := dirIn(command)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
