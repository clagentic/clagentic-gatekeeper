package identity

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// post sends a raw body, bypassing Client's marshalling.
func post(t *testing.T, c Client, path, body string) (int, string) {
	t.Helper()
	resp, err := c.http().Post("http://localhost"+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func TestRequestBodyMustBeExactlyOneJSONObject(t *testing.T) {
	c, f := startServer(t, nil)
	for name, body := range map[string]string{
		"two objects":      `{}{}`,
		"trailing garbage": `{} garbage`,
		"second document":  `{"definition":"example-builder"} {"definition":"example-merger"}`,
		"array":            `[]`,
		"null":             `null`,
		"empty":            ``,
		"truncated":        `{"definition":`,
		"unknown member":   `{"definitoin":"example-builder"}`,
	} {
		status, got := post(t, c, PathIssueSession, body)
		if status != 400 || !strings.Contains(got, `"error":"bad_request"`) {
			t.Errorf("%s: status %d body %s", name, status, got)
		}
		for _, parserText := range []string{"invalid character", "unexpected", "unknown field", "cannot unmarshal"} {
			if strings.Contains(got, parserText) {
				t.Errorf("%s: the response carries parser text %q: %s", name, parserText, got)
			}
		}
	}
	if entries, err := os.ReadDir(f.root); err == nil && len(entries) != 0 {
		t.Fatalf("a refused body still ran the operation: %v", entries)
	}
	if status, got := post(t, c, PathIssueSession, " {\"definition\":\"example-builder\"}\n "); status != 200 {
		t.Fatalf("a single object with surrounding whitespace: %d %s", status, got)
	}
}

func TestParentInvalidResponseCarriesNoParserText(t *testing.T) {
	c, f := startServer(t, nil)
	_, err := c.IssueChild(ChildRequest{ParentToken: "not.a.token", AgentType: "example-builder", AgentID: "a1"})
	ie, ok := IsIssueError(err)
	if !ok || ie.Code != "parent_invalid" || ie.Message != publicParentInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(f.logs.all(), "parent_invalid") {
		t.Fatalf("the cause was not logged: %q", f.logs.all())
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

// Listen never unlinks: whatever exists at the path, even a leftover socket
// nobody listens on, is refused by name and left exactly where it was.
func TestListenRefusesAnythingThatExistsAndLeavesItInPlace(t *testing.T) {
	for name, create := range map[string]func(t *testing.T, path string){
		"leftover socket": leaveStaleSocket,
		"regular file": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink(filepath.Join(filepath.Dir(path), "nowhere"), path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		path := filepath.Join(shortSocketDir(t), "s.sock")
		create(t, path)
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Listen(path, 0o600)
		if err == nil {
			l.Close()
			t.Errorf("%s: Listen replaced what was at the path", name)
			continue
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("%s: the refusal does not name the path: %v", name, err)
		}
		after, serr := os.Lstat(path)
		if serr != nil || !os.SameFile(before, after) {
			t.Errorf("%s: the entry at the path was removed or replaced: %v", name, serr)
		}
	}
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

func TestListenRefusalLeavesNoTemporaryName(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o600); err == nil {
		t.Fatal("an existing path was accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "s.sock" {
		t.Fatalf("directory after a refusal: %v %v", entries, err)
	}
}

// Closing the listener must not unlink the path: a replacement socket bound
// there by someone else after this server started has to survive an old
// listener closing.
func TestCloseDoesNotUnlinkTheSocketPath(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "s.sock")
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("Close removed the socket path: %v", err)
	}
}

// Shutdown can run before Serve registers the listener; Serve must still return.
func TestServeWithAnAlreadyCancelledContextReturns(t *testing.T) {
	f := newFixture(t, nil)
	path := filepath.Join(shortSocketDir(t), "s.sock")
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- (&Server{Issuer: f.issuer, Logf: f.logs.add}).Serve(ctx, l) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve blocked after its context was already cancelled")
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

func TestSocketServesJWKS(t *testing.T) {
	c, f := startServer(t, nil)
	doc, err := c.FetchJWKS()
	if err != nil || len(doc.Keys) != 1 || doc.Keys[0].Kid != f.issuer.Keys.Kid() {
		t.Fatalf("%+v %v", doc, err)
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
	runOtherUidSession(t)
}

// ancestorModes records mode and owner of every directory from dir up to /.
func ancestorModes(t *testing.T, dir string) map[string]string {
	t.Helper()
	modes := map[string]string{}
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		uid, _ := ownerUID(fi)
		modes[d] = fmt.Sprintf("%v uid=%d", fi.Mode(), uid)
		if filepath.Dir(d) == d {
			return modes
		}
	}
}

// The other-uid test must change nothing it did not create, so a killed or
// timed-out run cannot leave a host directory more permissive than it found it.
func TestOtherUidSessionLeavesEveryAncestorModeUnchanged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a peer under another uid")
	}
	before := ancestorModes(t, os.TempDir())
	runOtherUidSession(t)
	after := ancestorModes(t, os.TempDir())
	for d, want := range before {
		if after[d] != want {
			t.Errorf("%s changed from %q to %q", d, want, after[d])
		}
	}
}

// runOtherUidSession runs the helper under uid 65534 with a private (0700)
// TMPDIR, the shape of a scoped runner. The uid cannot search that directory, so
// the helper binary and the socket are reached through a directory descriptor
// the parent opened and passes down: the helper still does its own connect(),
// and the kernel records its uid. No path the test did not create is touched.
func runOtherUidSession(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a peer under another uid")
	}
	const otherUID = 65534
	private, err := os.MkdirTemp("", "gk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(private) })
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", private)
	c, f := startServer(t, nil)
	shared := filepath.Dir(c.Socket)
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "helper.test"), self, 0o755); err != nil {
		t.Fatal(err)
	}
	// shared is created by this test, so its mode may be set freely.
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	dirFD, err := os.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	defer dirFD.Close()
	// ExtraFiles[0] becomes descriptor 3 in the child.
	viaFD := "/proc/self/fd/3"
	cmd := exec.Command(viaFD+"/helper.test", "-test.run=^TestHelperProcess$")
	cmd.ExtraFiles = []*os.File{dirFD}
	cmd.Env = append(os.Environ(), helperEnvSocket+"="+viaFD+"/"+filepath.Base(c.Socket))
	runAsUID(cmd, otherUID)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper under uid %d could not run or connect through /proc/self/fd/3 (the environment denies exec or connect through a descriptor path): %v; stderr: %s", otherUID, err, stderr.String())
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
	if uid, _ := ownerUID(fi); uid != otherUID || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spawn dir owner %d mode %v", uid, fi.Mode().Perm())
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
