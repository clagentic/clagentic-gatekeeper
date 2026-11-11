//go:build linux

package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Unix(1792000000, 0)

func writeKey(t *testing.T, dir, name string, ec bool) string {
	t.Helper()
	var der []byte
	var err error
	if ec {
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			t.Fatal(gerr)
		}
		der, err = x509.MarshalPKCS8PrivateKey(k)
	} else {
		_, k, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			t.Fatal(gerr)
		}
		der, err = x509.MarshalPKCS8PrivateKey(k)
	}
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeDefinition(t *testing.T, dir, name, roles string) {
	t.Helper()
	body := "---\nname: " + name + "\nroles: [" + roles + "]\ntrust_boundary: example\n---\nbody text\n"
	if err := os.WriteFile(filepath.Join(dir, name+".md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeProc stands in for /proc only where a unit test needs a chosen
// executable; the socket tests read the real /proc.
func fakeProc(exe string, start uint64) ProcReader {
	return func(int32) (ProcInfo, error) {
		return ProcInfo{Exe: exe, Args: []string{exe}, StartTime: start, UID: uint32(os.Getuid()), HasUID: true}, nil
	}
}

// logSink collects server log lines for assertions.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) add(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type fixture struct {
	issuer *Issuer
	defs   string
	root   string
	logs   *logSink
}

// newFixture builds an issuer over synthetic definitions; mutate adjusts the
// settings.
func newFixture(t *testing.T, mutate func(*Settings)) *fixture {
	t.Helper()
	tmp := t.TempDir()
	defs := filepath.Join(tmp, "defs")
	if err := os.Mkdir(defs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, defs, "example-builder", "builder")
	writeDefinition(t, defs, "example-merger", "merger, builder")
	s := Settings{
		SocketPath: filepath.Join(tmp, "run", "identity.sock"), KeyPath: writeKey(t, tmp, "key.pem", false),
		DefinitionsDir: defs, SpawnRoot: filepath.Join(tmp, "spawn"),
	}
	if mutate != nil {
		mutate(&s)
	}
	iss, err := NewIssuer(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iss.Close)
	iss.Now = func() time.Time { return testNow }
	iss.Proc = fakeProc("/opt/example/example-runtime", 100)
	return &fixture{issuer: iss, defs: defs, root: s.SpawnRoot, logs: &logSink{}}
}

// newDefs opens dir as a definitions trust root and closes it with the test.
func newDefs(t *testing.T, dir string) *Definitions {
	t.Helper()
	d, err := NewDefinitions(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// failer is the part of testing.TB the guard helpers use, so a test can hand
// them a recorder and watch them fail.
type failer interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// requireNoEntries fails when dir cannot be listed or is not empty. A listing
// that errors proves nothing about what the directory holds, so it is a failure
// and never a pass.
func requireNoEntries(t failer, dir, what string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("%s: cannot list %s: %v", what, dir, err)
		return
	}
	if len(entries) != 0 {
		t.Fatalf("%s: %s holds %v", what, dir, entries)
	}
}

// runProbe runs a probe child and returns the first line it printed. A probe
// that could not be started skips, naming the precondition that is missing; a
// probe that started and failed is a failure, because the thing under test may
// be what broke it.
func runProbe(t failer, cmd *exec.Cmd, precondition string) string {
	t.Helper()
	raw, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("the probe ran and failed: %v: %s", err, exit.Stderr)
			return ""
		}
		t.Skipf("%s: %v", precondition, err)
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
}

func selfPeer(pid int32) Peer {
	return Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), PID: pid}
}
