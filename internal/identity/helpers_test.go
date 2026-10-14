package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

// writePublicOf writes the PKIX public half of the private key at keyPath, the
// only form retired_keys accepts.
func writePublicOf(t *testing.T, keyPath, dir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.(interface{ Public() crypto.PublicKey }).Public())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
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

type fixture struct {
	issuer *Issuer
	defs   string
	root   string
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
	iss.Now = func() time.Time { return testNow }
	iss.Proc = fakeProc("/opt/example/example-runtime", 100)
	return &fixture{issuer: iss, defs: defs, root: s.SpawnRoot}
}

func selfPeer(pid int32) Peer {
	return Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), PID: pid}
}
