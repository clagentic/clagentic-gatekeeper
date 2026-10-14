package identity

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const probeEnvPath = "IDENTITY_TEST_PROBE_PATH"

// TestProbeProcess is the body of a child that only tries to connect. It is a
// no-op in a normal test run.
func TestProbeProcess(t *testing.T) {
	p := os.Getenv(probeEnvPath)
	if p == "" {
		t.Skip("probe process only")
	}
	c, err := net.Dial("unix", p)
	if err != nil {
		os.Stdout.WriteString("refused: " + err.Error() + "\n")
		return
	}
	c.Close()
	os.Stdout.WriteString("connected\n")
}

// withUmask000 sets umask 000, the widest case, for the test and restores it.
func withUmask000(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

// prober runs connect attempts as uid 65534 from a directory the test created.
// The probe binary and the target are reached through a directory descriptor, so
// no path the test did not create is touched or its mode changed.
type prober struct {
	t      *testing.T
	shared string
	fd     *os.File
}

func newProber(t *testing.T) *prober {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to connect as another uid")
	}
	shared := shortSocketDir(t)
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "probe.test"), self, 0o755); err != nil {
		t.Fatal(err)
	}
	// shared was created by this test, so its mode may be set freely.
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fd.Close() })
	return &prober{t: t, shared: shared, fd: fd}
}

// connect returns the probe's one-line outcome for an absolute path under shared.
func (p *prober) connect(target string) string {
	p.t.Helper()
	rel, err := filepath.Rel(p.shared, target)
	if err != nil {
		p.t.Fatal(err)
	}
	const viaFD = "/proc/self/fd/3"
	cmd := exec.Command(viaFD+"/probe.test", "-test.run=^TestProbeProcess$")
	cmd.ExtraFiles = []*os.File{p.fd}
	cmd.Env = append(os.Environ(), probeEnvPath+"="+viaFD+"/"+rel)
	runAsUID(cmd, 65534)
	out, err := cmd.Output()
	if err != nil {
		p.t.Fatalf("probe could not run as uid 65534: %v", err)
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func setHook(t *testing.T, f func(privateDir, tempSocket string)) {
	t.Helper()
	listenAfterBind = f
	t.Cleanup(func() { listenAfterBind = nil })
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

// (a) The temporary socket lives in a directory only the serving uid can enter,
// even when the process umask would make everything world-accessible.
func TestListenTempSocketIsInsideAPrivate0700DirUnderUmask000(t *testing.T) {
	withUmask000(t)
	dir := shortSocketDir(t)
	var seen bool
	setHook(t, func(private, tmp string) {
		seen = true
		fi, err := os.Stat(private)
		if err != nil {
			t.Errorf("private dir: %v", err)
			return
		}
		if fi.Mode().Perm() != 0o700 || !fi.IsDir() {
			t.Errorf("private dir mode %v, want 0700", fi.Mode())
		}
		if uid, _ := ownerUID(fi); int(uid) != os.Getuid() {
			t.Errorf("private dir owner %d, want %d", uid, os.Getuid())
		}
		if filepath.Dir(private) != dir || filepath.Dir(tmp) != private {
			t.Errorf("temp socket %q is not in a private dir directly under %q", tmp, dir)
		}
	})
	l, err := Listen(filepath.Join(dir, "s.sock"), 0o666)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if !seen {
		t.Fatal("the hook did not run")
	}
}

// (b) A uid excluded by socket_mode cannot connect to the temporary name or to
// the final path, under umask 000. A uid the mode includes can, which shows the
// probe itself works.
func TestListenExcludedUidCannotConnectToAnyNameUnderUmask000(t *testing.T) {
	p := newProber(t)
	withUmask000(t)
	path := filepath.Join(p.shared, "s.sock")
	var atTemp string
	setHook(t, func(_, tmp string) { atTemp = p.connect(tmp) })
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if !strings.HasPrefix(atTemp, "refused") {
		t.Errorf("uid 65534 at the temporary name: %q", atTemp)
	}
	if got := p.connect(path); !strings.HasPrefix(got, "refused") {
		t.Errorf("uid 65534 at the final path with mode 0600: %q", got)
	}

	open := filepath.Join(p.shared, "open.sock")
	setHook(t, nil)
	ol, err := Listen(open, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	defer ol.Close()
	if got := p.connect(open); got != "connected" {
		t.Errorf("uid 65534 at a 0666 socket: %q, want connected", got)
	}
}

// (c) The final path carries socket_mode as soon as it exists, whatever the umask.
func TestListenFinalPathHasSocketModeUnderEveryUmask(t *testing.T) {
	for _, umask := range []int{0, 0o077, 0o022} {
		for _, mode := range []os.FileMode{0o600, 0o660, 0o666} {
			old := syscall.Umask(umask)
			dir := shortSocketDir(t)
			path := filepath.Join(dir, "s.sock")
			l, err := Listen(path, mode)
			syscall.Umask(old)
			if err != nil {
				t.Fatal(err)
			}
			fi, serr := os.Lstat(path)
			l.Close()
			if serr != nil {
				t.Fatal(serr)
			}
			if fi.Mode().Perm() != mode || fi.Mode()&os.ModeSocket == 0 {
				t.Errorf("umask %04o mode %v: final path is %v", umask, mode, fi.Mode())
			}
		}
	}
}

// (d) An existing final path is refused and left untouched, under umask 000.
func TestListenExistingFinalPathRefusedAndUntouchedUnderUmask000(t *testing.T) {
	withUmask000(t)
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o666); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("existing path: %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("existing path was changed: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatalf("existing file content changed: %q", b)
	}
}

// A failure after the bind names the path the operator configured and never the
// temporary staging path.
func TestListenErrorsNameThePublishedPathNotTheStagingPath(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	setHook(t, func(_, tmp string) { _ = os.Remove(tmp) })
	_, err := Listen(path, 0o600)
	if err == nil {
		t.Fatal("a vanished staging socket was accepted")
	}
	if !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), ".gk-") {
		t.Fatalf("error %q must name %s and not the staging path", err, path)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("the cause is no longer reachable: %v", err)
	}
}

// (e) No private directory is left behind, on success or on any failure.
func TestListenLeavesNoPrivateDirOnSuccessOrFailure(t *testing.T) {
	withUmask000(t)

	ok := shortSocketDir(t)
	l, err := Listen(filepath.Join(ok, "s.sock"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if got := dirEntries(t, ok); len(got) != 1 || got[0] != "s.sock" {
		t.Errorf("after success: %v", got)
	}

	taken := shortSocketDir(t)
	if err := os.WriteFile(filepath.Join(taken, "s.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(taken, "s.sock"), 0o600); err == nil {
		t.Fatal("existing path accepted")
	}
	if got := dirEntries(t, taken); len(got) != 1 || got[0] != "s.sock" {
		t.Errorf("after refusal: %v", got)
	}

	// A final name the filesystem rejects fails the link after the bind, a
	// different cleanup path from an existing target.
	long := shortSocketDir(t)
	if _, err := Listen(filepath.Join(long, strings.Repeat("x", 300)), 0o600); err == nil {
		t.Fatal("an over-long final name was accepted")
	}
	if got := dirEntries(t, long); len(got) != 0 {
		t.Errorf("after a link failure: %v", got)
	}
}
