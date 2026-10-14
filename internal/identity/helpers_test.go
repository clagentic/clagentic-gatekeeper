//go:build linux

package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
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
		return ProcInfo{Exe: exe, Args: []string{exe}, StartTime: start}, nil
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

// newFixture builds an issuer with an invented operator uid unless the test
// sets one.
func newFixture(t *testing.T, mutate func(*Settings)) *fixture {
	t.Helper()
	tmp := t.TempDir()
	defs := filepath.Join(tmp, "defs")
	if err := os.Mkdir(defs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, defs, "example-builder", "builder")
	writeDefinition(t, defs, "example-merger", "merger, builder")
	operator := uint32(os.Getuid()) + 1
	s := Settings{
		SocketPath: filepath.Join(tmp, "run", "identity.sock"), KeyPath: writeKey(t, tmp, "key.pem", false),
		OperatorUID: &operator, OperatorName: "example-operator", OperatorRoles: []string{"reader"},
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

func selfPeer(pid int32) Peer {
	return Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), PID: pid}
}
