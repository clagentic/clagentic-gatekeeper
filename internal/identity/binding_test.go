//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// procTree is a fake /proc: pid to what the kernel would report.
type procTree map[int32]ProcInfo

func (p procTree) reader() ProcReader {
	return func(pid int32) (ProcInfo, error) {
		info, ok := p[pid]
		if !ok {
			return ProcInfo{}, os.ErrNotExist
		}
		return info, nil
	}
}

type bindingFixture struct {
	*fixture
	tree procTree
	uid  uint32
	dev  uint64
	ino  uint64
}

// newBindingFixture builds an issuer that treats a real file as the gatekeeper
// client binary, over a fake /proc holding two runtimes (pids 100 and 200).
func newBindingFixture(t *testing.T) *bindingFixture {
	t.Helper()
	f := newFixture(t, nil)
	helper := filepath.Join(t.TempDir(), "gatekeeper")
	if err := os.WriteFile(helper, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	b := &bindingFixture{fixture: f, uid: uint32(os.Getuid()), dev: uint64(st.Dev), ino: st.Ino}
	b.tree = procTree{
		100: b.proc("/opt/example/claude", 50, 1, "claude"),
		200: b.proc("/opt/example/claude", 60, 1, "claude"),
	}
	f.issuer.HelperExe = helper
	f.issuer.Proc = func(pid int32) (ProcInfo, error) { return b.tree.reader()(pid) }
	return b
}

func (b *bindingFixture) proc(exe string, start uint64, ppid int32, args ...string) ProcInfo {
	return ProcInfo{Exe: exe, Args: args, StartTime: start, PPID: ppid, UID: b.uid, HasUID: true, ExeDev: 7, ExeIno: uint64(len(exe)) + start}
}

// hook adds a gatekeeper client process under ppid.
func (b *bindingFixture) hook(pid, ppid int32, start uint64) Peer {
	p := b.proc(b.issuer.HelperExe, start, ppid, "gatekeeper", "hook")
	p.ExeDev, p.ExeIno = b.dev, b.ino
	b.tree[pid] = p
	return selfPeer(pid)
}

func (b *bindingFixture) shell(pid, ppid int32, start uint64, args ...string) {
	b.tree[pid] = b.proc("/bin/sh", start, ppid, args...)
}

func child(token, id string) ChildRequest {
	return ChildRequest{ParentToken: token, AgentType: "example-builder", AgentID: id}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if ie, ok := IsIssueError(err); !ok || ie.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

// A hook is a new process for every event. A session issued to one hook and a
// child requested by another both bind to the runtime that is their parent.
func TestHookWhoseParentIsTheRuntimeGetsAChildBoundToThatRuntime(t *testing.T) {
	b := newBindingFixture(t)
	start := b.hook(150, 100, 300)
	later := b.hook(151, 100, 310)

	session, c := mustSession(t, b.fixture, start, SessionRequest{})
	if c.RT.ID != "claude" || c.Sub != "runtime:claude" {
		t.Fatalf("the runtime id came from the hook, not the runtime: rt=%+v sub=%s", c.RT, c.Sub)
	}
	bound, ok := b.issuer.Registry.get(c.Jti)
	if !ok || bound.pid != 100 || bound.startTime != 50 {
		t.Fatalf("the session is bound to %+v, want runtime pid 100", bound)
	}
	out, err := b.issuer.IssueChild(later, child(session.Token, "a1"))
	if err != nil || out.Grade != "harness" {
		t.Fatalf("a hook under the same runtime: %+v %v", out, err)
	}
}

func TestHookUnderADifferentRuntimeIsRefused(t *testing.T) {
	b := newBindingFixture(t)
	session, _ := mustSession(t, b.fixture, b.hook(150, 100, 300), SessionRequest{})
	other := b.hook(250, 200, 310)
	_, err := b.issuer.IssueChild(other, child(session.Token, "a1"))
	wantCode(t, err, CodePIDMismatch)
}

// The same pid under a new start time is another process: a runtime that
// restarted does not inherit the sessions of the one it replaced.
func TestHookUnderARestartedRuntimeIsRefused(t *testing.T) {
	b := newBindingFixture(t)
	session, _ := mustSession(t, b.fixture, b.hook(150, 100, 300), SessionRequest{})
	b.tree[100] = b.proc("/opt/example/claude", 5000, 1, "claude")
	_, err := b.issuer.IssueChild(b.hook(151, 100, 5100), child(session.Token, "a1"))
	wantCode(t, err, CodePIDMismatch)
}

func TestShellCommandWrapperBetweenHookAndRuntimeIsClimbedThrough(t *testing.T) {
	b := newBindingFixture(t)
	b.shell(120, 100, 250, "sh", "-c", "gatekeeper hook")
	b.shell(121, 100, 251, "sh", "-c", "gatekeeper hook")
	session, c := mustSession(t, b.fixture, b.hook(150, 120, 300), SessionRequest{})
	if c.RT.ID != "claude" {
		t.Fatalf("rt %+v", c.RT)
	}
	// Direct and wrapped hooks of one runtime agree on the binding.
	if _, err := b.issuer.IssueChild(b.hook(152, 100, 320), child(session.Token, "a1")); err != nil {
		t.Fatalf("direct hook: %v", err)
	}
	if _, err := b.issuer.IssueChild(b.hook(151, 121, 310), child(session.Token, "a2")); err != nil {
		t.Fatalf("wrapped hook: %v", err)
	}
}

func TestOnlyACommandStringShellIsAWrapper(t *testing.T) {
	cases := []struct {
		exe  string
		args []string
		want bool
	}{
		{"/bin/sh", []string{"sh", "-c", "x"}, true},
		{"/bin/bash", []string{"bash", "-lc", "x"}, true},
		{"/bin/bash", []string{"bash", "-c", "-l", "x"}, true},
		{"/bin/bash", []string{"bash", "--noprofile", "-c", "x"}, true},
		{"/bin/sh", []string{"sh", "script.sh"}, false},
		{"/bin/bash", []string{"bash"}, false},
		{"/bin/bash", []string{"bash", "-i"}, false},
		{"/bin/bash", []string{"bash", "script.sh", "-c"}, false},
		{"/bin/sh", []string{"sh"}, false},
		{"/bin/sh", nil, false},
		{"/usr/bin/python3", []string{"python3", "-c", "x"}, false},
	}
	for _, c := range cases {
		if got := isCommandWrapper(ProcInfo{Exe: c.exe, Args: c.args}); got != c.want {
			t.Errorf("%s %v: got %v, want %v", c.exe, c.args, got, c.want)
		}
	}
}

func TestShellRunningAScriptIsTheRuntimeNotAWrapper(t *testing.T) {
	b := newBindingFixture(t)
	b.shell(120, 100, 250, "sh", "launcher.sh")
	_, c := mustSession(t, b.fixture, b.hook(150, 120, 300), SessionRequest{})
	if c.RT.ID != "launcher" {
		t.Fatalf("rt %+v: a script shell must name the runtime", c.RT)
	}
}

func TestTooManyWrappersRefuse(t *testing.T) {
	b := newBindingFixture(t)
	b.shell(130, 100, 250, "sh", "-c", "x")
	b.shell(131, 130, 251, "sh", "-c", "x")
	b.shell(132, 131, 252, "sh", "-c", "x")
	b.shell(133, 132, 253, "sh", "-c", "x")
	_, err := b.issuer.IssueSession(b.hook(150, 133, 300), SessionRequest{})
	wantCode(t, err, CodeRuntimeUnbound)
	b.tree[133] = b.proc("/opt/example/claude", 253, 1, "claude")
	b.hook(151, 133, 300)
	if _, err := b.issuer.IssueSession(selfPeer(151), SessionRequest{}); err != nil {
		t.Fatalf("three wrappers must be accepted: %v", err)
	}
}

func TestAncestryViolationsRefuseWithoutIssuing(t *testing.T) {
	cases := map[string]func(b *bindingFixture) Peer{
		"parent is init": func(b *bindingFixture) Peer { return b.hook(150, 1, 300) },
		"orphan, parent 0": func(b *bindingFixture) Peer {
			return b.hook(150, 0, 300)
		},
		"runtime of another uid": func(b *bindingFixture) Peer {
			p := b.tree[100]
			p.UID++
			b.tree[100] = p
			return b.hook(150, 100, 300)
		},
		"runtime with unknown uid": func(b *bindingFixture) Peer {
			p := b.tree[100]
			p.HasUID = false
			b.tree[100] = p
			return b.hook(150, 100, 300)
		},
		"parent younger than its child": func(b *bindingFixture) Peer {
			return b.hook(150, 100, 10)
		},
		"wrapper of another uid": func(b *bindingFixture) Peer {
			b.shell(120, 100, 250, "sh", "-c", "x")
			p := b.tree[120]
			p.UID++
			b.tree[120] = p
			return b.hook(150, 120, 300)
		},
	}
	for name, setup := range cases {
		b := newBindingFixture(t)
		peer := setup(b)
		_, err := b.issuer.IssueSession(peer, SessionRequest{})
		if ie, ok := IsIssueError(err); !ok || ie.Code != CodeRuntimeUnbound {
			t.Errorf("%s: got %v", name, err)
		}
		if entries, rerr := os.ReadDir(b.root); rerr == nil && len(entries) != 0 {
			t.Errorf("%s: a refusal left delivery directories: %v", name, entries)
		}
	}
}

func TestUnreadableProcRefusesSessionAndChild(t *testing.T) {
	b := newBindingFixture(t)
	hook := b.hook(150, 100, 300)
	session, _ := mustSession(t, b.fixture, hook, SessionRequest{})
	// The runtime disappears: its /proc entry cannot be read.
	delete(b.tree, 100)
	_, err := b.issuer.IssueSession(hook, SessionRequest{})
	wantCode(t, err, CodePeerUnattested)
	_, err = b.issuer.IssueChild(hook, child(session.Token, "a1"))
	wantCode(t, err, CodePeerUnattested)

	b.tree[100] = b.proc("/opt/example/claude", 50, 1, "claude")
	b.issuer.Proc = func(int32) (ProcInfo, error) { return ProcInfo{}, os.ErrPermission }
	_, err = b.issuer.IssueSession(hook, SessionRequest{})
	wantCode(t, err, CodePeerUnattested)
	if entries, rerr := os.ReadDir(b.root); rerr != nil || len(entries) != 1 {
		t.Fatalf("refusals left delivery directories: %v %v", entries, rerr)
	}
}

// A process that is replaced between the walk and the re-read cannot carry the
// binding of the one it replaced.
func TestAncestryThatChangesDuringTheWalkRefuses(t *testing.T) {
	b := newBindingFixture(t)
	hook := b.hook(150, 100, 300)
	reads := map[int32]int{}
	b.issuer.Proc = func(pid int32) (ProcInfo, error) {
		reads[pid]++
		info, err := b.tree.reader()(pid)
		if pid == 100 && reads[pid] > 1 {
			info.StartTime = 9999
		}
		return info, err
	}
	_, err := b.issuer.IssueSession(hook, SessionRequest{})
	wantCode(t, err, CodeRuntimeUnbound)
}

// No request member names, selects or extends the walk: the same peer gets the
// same binding whatever the request says.
func TestRequestContentCannotChangeTheBinding(t *testing.T) {
	b := newBindingFixture(t)
	hook := b.hook(150, 100, 300)
	for _, req := range []SessionRequest{
		{},
		{Definition: "example-builder"},
		{Origin: "agent", Runtime: &RuntimeDecl{ID: "claude", Version: "1.0.0"}},
	} {
		out, err := b.issuer.IssueSession(hook, req)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		c, err := b.issuer.Keys.ParseOwn(out.Token)
		if err != nil {
			t.Fatal(err)
		}
		if bound, ok := b.issuer.Registry.get(c.Jti); !ok || bound.pid != 100 {
			t.Fatalf("%+v bound to %+v", req, bound)
		}
	}
	if _, err := b.issuer.IssueSession(hook, SessionRequest{Runtime: &RuntimeDecl{ID: "someone-else"}}); err == nil {
		t.Fatal("a declared runtime id other than the bound runtime's was accepted")
	}
}

func TestPeerThatIsNotTheClientBinaryIsItsOwnRuntime(t *testing.T) {
	b := newBindingFixture(t)
	b.tree[300] = b.proc("/opt/example/direct-client", 400, 100, "direct-client")
	_, c := mustSession(t, b.fixture, selfPeer(300), SessionRequest{})
	if c.RT.ID != "direct-client" {
		t.Fatalf("rt %+v", c.RT)
	}
	if bound, _ := b.issuer.Registry.get(c.Jti); bound.pid != 300 {
		t.Fatalf("bound to %+v", bound)
	}
}
