//go:build linux

package hook

import (
	"encoding/json"
	"errors"
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

const testRid = "0123456789abcdef0123456789abcdef"

// fakeProvider answers a fixed origin kind or error and counts its runs.
type fakeProvider struct {
	kind string
	err  error
	runs int
}

func (f *fakeProvider) TurnOrigin([]byte) (string, error) {
	f.runs++
	return f.kind, f.err
}

// The turn-origin order, one row per rung and per way a rung can fail.
func TestClassifyTurn(t *testing.T) {
	human := &fakeProvider{kind: "human"}
	notTyped := &fakeProvider{kind: "task-notification"}
	failing := &fakeProvider{err: errors.New("exit status 1")}
	has := func(source string) Payload { return Payload{SourcePresent: true, Source: source} }
	hostSet := func(string) string { return "1" }
	hostUnset := func(string) string { return "" }
	with := func(p OriginProvider) func() (OriginProvider, error) {
		return func() (OriginProvider, error) { return p, nil }
	}
	broken := func() (OriginProvider, error) { return nil, errors.New("config unreadable") }

	for _, tc := range []struct {
		name   string
		p      Payload
		lookup func() (OriginProvider, error)
		env    func(string) string
		typed  bool
		rung   int
		reason string
	}{
		{"source user", has("user"), nil, hostSet, true, 1, "source is user"},
		{"source user beats a provider that says not human", has("user"), with(notTyped), hostSet, true, 1, "source is user"},
		{"source sdk", has("sdk"), with(human), hostUnset, false, 2, `"sdk"`},
		{"source system", has("system"), nil, hostUnset, false, 2, `"system"`},
		{"source loop_wakeup", has("loop_wakeup"), nil, hostUnset, false, 2, `"loop_wakeup"`},
		{"source schedule_wakeup", has("schedule_wakeup"), nil, hostUnset, false, 2, `"schedule_wakeup"`},
		{"source poll_event", has("poll_event"), nil, hostUnset, false, 2, `"poll_event"`},
		{"source present but not a string", has(""), with(human), hostUnset, false, 2, `""`},
		{"no source, provider says human", Payload{}, with(human), hostSet, true, 3, "human"},
		{"no source, provider says human, host unset", Payload{}, with(human), hostUnset, true, 3, "human"},
		{"no source, provider says task-notification", Payload{}, with(notTyped), hostUnset, false, 3, `"task-notification"`},
		{"no source, provider fails", Payload{}, with(failing), hostUnset, false, 3, "exit status 1"},
		{"no source, provider cannot be set up", Payload{}, broken, hostUnset, false, 3, "config unreadable"},
		{"no source, no provider, host unset", Payload{}, nil, hostUnset, true, 4, "declares no injected turns"},
		{"no source, configured but absent provider, host unset", Payload{}, with(nil), hostUnset, true, 4, "declares no injected turns"},
		{"no source, no provider, host set", Payload{}, nil, hostSet, false, 5, "no origin was available"},
		{"no source, no environment reader", Payload{}, nil, nil, true, 4, "declares no injected turns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyTurn(tc.p, []byte(`{}`), tc.lookup, tc.env)
			if got.Typed != tc.typed || got.Rung != tc.rung || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("got %+v, want typed=%v rung=%d reason containing %q", got, tc.typed, tc.rung, tc.reason)
			}
		})
	}

	// A rung that decides earlier never loads or runs the provider.
	loaded := 0
	lookup := func() (OriginProvider, error) { loaded++; return human, nil }
	ClassifyTurn(has("user"), nil, lookup, hostSet)
	ClassifyTurn(has("sdk"), nil, lookup, hostSet)
	if loaded != 0 {
		t.Fatalf("the provider was loaded %d times for a payload that names its source", loaded)
	}
}

// One table for the provider command: what it must print to be believed, and
// every way it can fail to say so.
func TestCommandProviderAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
		kind    string
		fail    string
	}{
		{"human", `printf '{"origin":{"kind":"human"}}'`, time.Second, "human", ""},
		{"human with more members", `printf '{"origin":{"kind":"human","subkind":"x"},"extra":1}\n'`, time.Second, "human", ""},
		{"another kind", `printf '{"origin":{"kind":"task-notification"}}'`, time.Second, "task-notification", ""},
		{"payload on stdin", `grep -q '"prompt"' && printf '{"origin":{"kind":"human"}}'`, time.Second, "human", ""},
		{"exits non-zero", `printf '{"origin":{"kind":"human"}}'; exit 3`, time.Second, "", "run"},
		{"garbage", `printf 'human'`, time.Second, "", "not a JSON object"},
		{"empty output", `true`, time.Second, "", "not a JSON object"},
		{"no kind", `printf '{"origin":{}}'`, time.Second, "", "no origin.kind"},
		{"two objects", `printf '{"origin":{"kind":"human"}}{}'`, time.Second, "", "more than one"},
		{"oversized output", `head -c 5000 /dev/zero | tr '\0' 'a'`, time.Second, "", "over"},
		{"times out", `exec sleep 10`, 200 * time.Millisecond, "", "timed out"},
		{"no positive timeout", `printf '{"origin":{"kind":"human"}}'`, 0, "", "timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, err := CommandProvider{Argv: []string{"/bin/sh", "-c", tc.script}, Timeout: tc.timeout}.TurnOrigin([]byte(`{"prompt":"x"}`))
			if tc.fail == "" {
				if err != nil || kind != tc.kind {
					t.Fatalf("got %q, %v", kind, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.fail) {
				t.Fatalf("got %q, %v, want an error containing %q", kind, err, tc.fail)
			}
		})
	}
	if _, err := (CommandProvider{Argv: []string{"/nonexistent/provider"}, Timeout: time.Second}).TurnOrigin(nil); err == nil {
		t.Fatal("a program that does not exist answered")
	}
	if _, err := (CommandProvider{Timeout: time.Second}).TurnOrigin(nil); err == nil {
		t.Fatal("an empty argv answered")
	}
}

// grantServer answers approval/grant over a unix socket and records what it was
// sent, so the hook is exercised through the real client.
type grantServer struct {
	Socket string

	mu     sync.Mutex
	grants []identity.ApprovalGrantRequest
	refuse string
}

// refuseWith makes every later grant answer with the given approval code.
func (g *grantServer) refuseWith(code string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refuse = code
}

func newGrantServer(t *testing.T) *grantServer {
	t.Helper()
	base, err := os.MkdirTemp("", "gkg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	g := &grantServer{Socket: filepath.Join(base, "g.sock")}
	l, err := net.Listen("unix", g.Socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+identity.PathApprovalGrant, func(w http.ResponseWriter, r *http.Request) {
		var req identity.ApprovalGrantRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.grants = append(g.grants, req)
		if g.refuse != "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": g.refuse, "message": "refused"})
			return
		}
		_ = json.NewEncoder(w).Encode(identity.ApprovalGranted{Rid: req.Rid, ExpiresAt: 1})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return g
}

func (g *grantServer) requests() []identity.ApprovalGrantRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]identity.ApprovalGrantRequest(nil), g.grants...)
}

// approvalHarness is a hook with a started session, a grant endpoint and a fake
// provider, on a host that declares no injected turns.
func approvalHarness(t *testing.T) (*harness, *grantServer, *fakeProvider) {
	t.Helper()
	h := newHarness(t, ModeEnforce)
	g := newGrantServer(t)
	prov := &fakeProvider{kind: "human"}
	h.hook.Granter = identity.Client{Socket: g.Socket, Timeout: 2 * time.Second}
	h.hook.Getenv = func(string) string { return "" }
	h.hook.TurnOrigin = func() (OriginProvider, error) { return prov, nil }
	startSession(t, h, "")
	return h, g, prov
}

func promptPayload(prompt string, extra ...any) map[string]any {
	p := map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": testSession, "prompt": prompt}
	for i := 0; i < len(extra); i += 2 {
		p[extra[i].(string)] = extra[i+1]
	}
	return p
}

// The phrase table: what is and is not the approval phrase, and what the hook
// does and does not ask of the issuer and of the provider.
func TestApprovePhrase(t *testing.T) {
	phrase := "approve " + testRid
	for _, tc := range []struct {
		name     string
		prompt   string
		extra    []any
		hostSet  bool
		noProv   bool
		refuse   string
		grants   int
		provRuns int
		logHas   string
	}{
		{name: "exact phrase, typed by the provider", prompt: phrase, grants: 1, provRuns: 1, logHas: "granted"},
		{name: "surrounding whitespace", prompt: "  \n" + phrase + "\t\n", grants: 1, provRuns: 1, logHas: "granted"},
		{name: "source user, provider not asked", prompt: phrase, extra: []any{"source", "user"}, grants: 1, logHas: "granted"},
		{name: "source sdk", prompt: phrase, extra: []any{"source", "sdk"}, logHas: "rung 2"},
		{name: "source loop_wakeup", prompt: phrase, extra: []any{"source", "loop_wakeup"}, logHas: "rung 2"},
		{name: "source null reads as absent", prompt: phrase, extra: []any{"source", nil}, grants: 1, provRuns: 1, logHas: "granted"},
		{name: "no provider, host declares no injected turns", prompt: phrase, noProv: true, grants: 1, logHas: "rung 4"},
		{name: "no provider, host can inject turns", prompt: phrase, noProv: true, hostSet: true, logHas: "no origin was available"},
		{name: "extra words", prompt: phrase + " please"},
		{name: "phrase inside a sentence", prompt: "ok, " + phrase},
		{name: "upper case", prompt: "Approve " + testRid},
		{name: "short rid", prompt: "approve " + testRid[:31]},
		{name: "two spaces", prompt: "approve  " + testRid},
		{name: "no prompt member", prompt: ""},
		{name: "issuer refuses the rid", prompt: phrase, refuse: "approval_unknown", grants: 1, provRuns: 1, logHas: "approval_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, g, prov := approvalHarness(t)
			g.refuseWith(tc.refuse)
			if tc.hostSet {
				h.hook.Getenv = func(string) string { return "1" }
			}
			if tc.noProv {
				h.hook.TurnOrigin = nil
			}
			token, _ := os.ReadFile(filepath.Join(sessionDir(t, h), identity.DeliveryFile))
			res := h.fire(EventUserPromptSubmit, promptPayload(tc.prompt, tc.extra...))
			if len(res.Stdout) != 0 || len(res.Stderr) != 0 || res.ExitCode != 0 {
				t.Fatalf("the hook answered the prompt: %+v", res)
			}
			got := g.requests()
			if len(got) != tc.grants || prov.runs != tc.provRuns {
				t.Fatalf("grant calls %d (want %d), provider runs %d (want %d)\n%s", len(got), tc.grants, prov.runs, tc.provRuns, h.log())
			}
			if tc.grants > 0 && (got[0].Rid != testRid || got[0].Token != strings.TrimSpace(string(token))) {
				t.Fatalf("the grant carried %+v, want rid %s and the session's assertion", got[0], testRid)
			}
			if !strings.Contains(h.log(), tc.logHas) {
				t.Fatalf("the log lacks %q:\n%s", tc.logHas, h.log())
			}
		})
	}
}

// The grant goes first and presents the assertion the request was made under;
// the refresh that follows is unchanged, and the grant does not need it enabled.
func TestApprovePhraseAndRefreshShareOneEvent(t *testing.T) {
	h, g, _ := approvalHarness(t)
	h.hook.RefreshBelow = 10 * time.Minute
	h.fake.TTL = 3600
	before, _ := os.ReadFile(filepath.Join(sessionDir(t, h), identity.DeliveryFile))
	h.hook.Now = func() time.Time { return time.Now().Add(55 * time.Minute) }
	h.fire(EventUserPromptSubmit, promptPayload("approve "+testRid))
	got := g.requests()
	if len(got) != 1 || got[0].Token != strings.TrimSpace(string(before)) {
		t.Fatalf("the grant did not present the pre-refresh assertion: %+v", got)
	}
	if s, _ := h.fake.counts(); s != 2 {
		t.Fatalf("the refresh did not run: %d session requests", s)
	}
}

func TestApprovePhraseWithoutASessionOrAnIssuerGrantsNothing(t *testing.T) {
	h, g, _ := approvalHarness(t)
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": "other-session", "prompt": "approve " + testRid})
	if len(g.requests()) != 0 || !strings.Contains(h.log(), "no session assertion") {
		t.Fatalf("a session with no record was granted for: %s", h.log())
	}
	h.hook.Granter = nil
	res := h.fire(EventUserPromptSubmit, promptPayload("approve "+testRid))
	if len(res.Stdout) != 0 || !strings.Contains(h.log(), "no issuer") {
		t.Fatalf("%+v\n%s", res, h.log())
	}
	h.hook.Granter = UnavailableIssuer{Err: errors.New("no socket")}
	res = h.fire(EventUserPromptSubmit, promptPayload("approve "+testRid))
	if len(res.Stdout) != 0 || res.ExitCode != 0 || !strings.Contains(h.log(), "no socket") {
		t.Fatalf("%+v\n%s", res, h.log())
	}
}

// Every prompt that is not the phrase leaves the hook exactly as it was: no
// grant, no provider, no output.
func TestOrdinaryPromptsNeverReachTheProviderOrTheIssuer(t *testing.T) {
	h, g, prov := approvalHarness(t)
	for _, prompt := range []string{"hello", "approve", "approve me", "run approve " + testRid + " now", ""} {
		if res := h.fire(EventUserPromptSubmit, promptPayload(prompt)); len(res.Stdout) != 0 || res.ExitCode != 0 {
			t.Fatalf("%q: %+v", prompt, res)
		}
	}
	if len(g.requests()) != 0 || prov.runs != 0 {
		t.Fatalf("%d grants, %d provider runs for prompts that are not the phrase", len(g.requests()), prov.runs)
	}
}
