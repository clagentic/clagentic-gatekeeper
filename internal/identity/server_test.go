package identity

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnvSocket = "IDENTITY_TEST_HELPER_SOCKET"
	helperEnvToken  = "IDENTITY_TEST_HELPER_TOKEN"
)

// TestHelperProcess is the body of a child process that talks to the server
// over the real socket. It is a no-op in a normal test run.
func TestHelperProcess(t *testing.T) {
	sock := os.Getenv(helperEnvSocket)
	if sock == "" {
		t.Skip("helper process only")
	}
	c := Client{Socket: sock}
	if tok := os.Getenv(helperEnvToken); tok != "" {
		_, err := c.IssueChild(ChildRequest{ParentToken: tok, AgentType: "example-builder", AgentID: "from-launcher"})
		if err == nil {
			os.Stdout.WriteString("child:issued\n")
		} else {
			os.Stdout.WriteString("child:" + err.Error() + "\n")
		}
	}
	out, err := c.IssueSession(SessionRequest{})
	if err != nil {
		os.Stdout.WriteString("session:" + err.Error() + "\n")
	} else {
		os.Stdout.WriteString("session:" + out.Subject + " " + out.Actor + "\n")
	}
}

func startServer(t *testing.T, mutate func(*Settings)) (Client, *fixture) {
	t.Helper()
	f := newFixture(t, mutate)
	// The socket tests read the real /proc and real SO_PEERCRED.
	f.issuer.Proc = ReadProc
	f.issuer.Now = time.Now
	// A unix socket path is limited to 108 bytes, shorter than t.TempDir().
	short, err := os.MkdirTemp("", "gk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	sock := filepath.Join(short, "s.sock")
	if len(sock) >= 108 {
		t.Fatalf("socket path %q is %d bytes, over the 108-byte sun_path limit; point TMPDIR at a shorter directory", sock, len(sock))
	}
	l, err := Listen(sock, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Issuer: f.issuer, Logf: f.logs.add}).Serve(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return Client{Socket: sock}, f
}

func TestSocketNonOperatorGetsWorkloadRuntime(t *testing.T) {
	c, _ := startServer(t, nil)
	out, err := c.IssueSession(SessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(out.Subject, "human:") || !strings.HasPrefix(out.Actor, "runtime:") || out.Grade != "workload" {
		t.Fatalf("%+v", out)
	}
}

func TestRefusalExposesStableMessageAndLogsInternalDetailOnly(t *testing.T) {
	c, f := startServer(t, nil)
	// Removing the spawn root makes directory creation fail with an error that
	// names the filesystem path.
	if err := os.RemoveAll(f.root); err != nil {
		t.Fatal(err)
	}
	_, err := c.IssueSession(SessionRequest{})
	ie, ok := IsIssueError(err)
	if !ok || ie.Code != "spawn_dir" || ie.Status != 500 {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(ie.Message, f.root) || strings.Contains(ie.Message, "no such file") || strings.Contains(ie.Message, os.TempDir()) {
		t.Fatalf("the response leaked internal detail: %q", ie.Message)
	}
	if !strings.Contains(f.logs.all(), f.root) {
		t.Fatalf("the internal cause was not logged server-side: %q", f.logs.all())
	}
}

func TestUnknownDefinitionResponseDoesNotCarryParseDetail(t *testing.T) {
	c, f := startServer(t, nil)
	if err := os.WriteFile(filepath.Join(f.defs, "example-broken.md"), []byte("---\nname: [unterminated\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := c.IssueSession(SessionRequest{Definition: "example-broken"})
	ie, ok := IsIssueError(err)
	if !ok || ie.Code != "definition_unknown" || ie.Message != `definition "example-broken" is not available` {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(f.logs.all(), "example-broken") {
		t.Fatalf("definition failure not logged: %q", f.logs.all())
	}
}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if len(filepath.Join(dir, "s.sock")) >= 108 {
		t.Fatalf("socket directory %q is too long for sun_path; point TMPDIR at a shorter directory", dir)
	}
	return dir
}

// leaveStaleSocket binds a socket and closes it without unlinking, the state a
// crashed server leaves behind.
func leaveStaleSocket(t *testing.T, path string) {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenReplacesASocketNobodyListensOn(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "s.sock")
	leaveStaleSocket(t, path)
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatalf("a refused, owned, stale socket was not replaced: %v", err)
	}
	l.Close()
}

func TestListenRefusesALiveServer(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "s.sock")
	first, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Listen(path, 0o600); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("second listener on a live socket: %v", err)
	}
}

func TestListenKeepsASocketWhoseProbeIsInconclusive(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "s.sock")
	leaveStaleSocket(t, path)
	real := probeSocket
	probeSocket = func(string) error { return os.ErrDeadlineExceeded }
	t.Cleanup(func() { probeSocket = real })
	_, err := Listen(path, 0o600)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("an inconclusive probe did not refuse, naming the path: %v", err)
	}
	if _, serr := os.Lstat(path); serr != nil {
		t.Fatalf("the socket path was unlinked on an inconclusive probe: %v", serr)
	}
}

func TestListenRefusesASocketOwnedByAnotherUid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand a socket file to another uid")
	}
	path := filepath.Join(shortSocketDir(t), "s.sock")
	leaveStaleSocket(t, path)
	if err := os.Lchown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o600); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("a socket owned by another uid was replaced: %v", err)
	}
	if _, serr := os.Lstat(path); serr != nil {
		t.Fatalf("the socket path was unlinked: %v", serr)
	}
}

func TestListenRefusesANonSocketPath(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "s.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o600); err == nil {
		t.Fatal("a regular file was replaced by a socket")
	}
}

func TestSocketOperatorGetsHuman(t *testing.T) {
	uid := uint32(os.Getuid())
	c, _ := startServer(t, func(s *Settings) { s.OperatorUID = &uid })
	out, err := c.IssueSession(SessionRequest{})
	if err != nil || out.Subject != "human:example-operator" {
		t.Fatalf("%+v %v", out, err)
	}
	out, err = c.IssueSession(SessionRequest{Runtime: &RuntimeDecl{}})
	if err != nil || out.Subject != "human:example-operator" || !strings.HasPrefix(out.Actor, "runtime:") {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestSocketServesJWKSAndSelfCheck(t *testing.T) {
	c, f := startServer(t, nil)
	doc, err := c.FetchJWKS()
	if err != nil || len(doc.Keys) != 1 || doc.Keys[0].Kid != f.issuer.Keys.Kid() {
		t.Fatalf("%+v %v", doc, err)
	}
	jwks := filepath.Join(t.TempDir(), "jwks.json")
	if err := f.issuer.Keys.WriteJWKS(jwks); err != nil {
		t.Fatal(err)
	}
	for _, ch := range SelfCheck(c, jwks, 0, time.Now()) {
		if !ch.OK {
			t.Errorf("%+v", ch)
		}
	}
	other, err := LoadKeyring(writeKey(t, t.TempDir(), "other.pem", false), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.WriteJWKS(jwks); err != nil {
		t.Fatal(err)
	}
	checks := SelfCheck(c, jwks, 0, time.Now())
	if checks[len(checks)-1].OK {
		t.Fatalf("stale jwks file reported fresh: %+v", checks)
	}
	gone := SelfCheck(Client{Socket: c.Socket + ".gone"}, jwks, 0, time.Now())
	if len(gone) != 1 || gone[0].OK {
		t.Fatalf("%+v", gone)
	}
}

func runHelper(t *testing.T, sock, parentToken string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnvSocket+"="+sock, helperEnvToken+"="+parentToken)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	return string(out)
}

// A peer running under a different uid is attested by the kernel, not by
// anything it says. Needs root to switch uid; skipped otherwise.
func TestSocketRealOtherUidGetsWorkloadAndOwnDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a peer under another uid")
	}
	const otherUID = 65534
	c, f := startServer(t, nil)
	shared := filepath.Dir(c.Socket)
	bin := filepath.Join(shared, "helper.test")
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnvSocket+"="+c.Socket)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: otherUID, Gid: otherUID}}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper under uid %d: %v", otherUID, err)
	}
	if !strings.Contains(string(out), "session:runtime:helper.test runtime:helper.test") {
		t.Fatalf("got %q", out)
	}
	entries, err := os.ReadDir(f.root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("spawn dirs: %v %v", entries, err)
	}
	fi, err := os.Stat(filepath.Join(f.root, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != otherUID || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spawn dir owner %d mode %v", st.Uid, fi.Mode().Perm())
	}
}

func TestSocketChildSamePidAndOtherPid(t *testing.T) {
	c, _ := startServer(t, nil)
	parent, err := c.IssueSession(SessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.IssueChild(ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "same-pid"})
	if err != nil || child.Grade != "harness" {
		t.Fatalf("same pid: %+v %v", child, err)
	}

	got := runHelper(t, c.Socket, parent.Token)
	if !strings.Contains(got, "child:parent_pid_mismatch") || !strings.Contains(got, "was issued to pid") {
		t.Fatalf("other pid was not refused with the mismatch: %q", got)
	}
	// The process-launcher child can still obtain its own workload session.
	if !strings.Contains(got, "session:runtime:") {
		t.Fatalf("launcher child got no session of its own: %q", got)
	}
}
