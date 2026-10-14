//go:build unix

package vectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// These tests hold the issuer to the contract: whatever it signs must pass the
// same reference verifier that proves the published vectors.

func issuerKey(t *testing.T, dir string, es bool) string {
	t.Helper()
	var der []byte
	var err error
	if es {
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
	p := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIssuedAssertionsPassConformance(t *testing.T) {
	for _, es := range []bool{false, true} {
		dir := t.TempDir()
		defs := filepath.Join(dir, "defs")
		if err := os.Mkdir(defs, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: example-builder\nroles: [builder]\ntrust_boundary: example\n---\n"
		if err := os.WriteFile(filepath.Join(defs, "example-builder.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		operator := uint32(os.Getuid())
		iss, err := identity.NewIssuer(identity.Settings{
			SocketPath: filepath.Join(dir, "run", "identity.sock"), KeyPath: issuerKey(t, dir, es),
			OperatorUID: &operator, OperatorName: "example-operator", OperatorRoles: []string{"reader"},
			DefinitionsDir: defs, SpawnRoot: filepath.Join(dir, "spawn"),
		})
		if err != nil {
			t.Fatal(err)
		}
		pid := int32(os.Getpid())
		peer := identity.Peer{UID: operator, GID: uint32(os.Getgid()), PID: pid}
		other := identity.Peer{UID: operator + 1, GID: peer.GID, PID: pid}

		raw, err := iss.Keys.MarshalJWKS()
		if err != nil {
			t.Fatal(err)
		}
		var doc jwksDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		tr := trust{iss.Issuer: doc}

		check := func(name, token, issuedDir string, wantGrade string) {
			t.Helper()
			v := vector{Kind: "token", Mode: audienceLocal, Now: time.Now().Unix(), ObservedDir: issuedDir, Token: token}
			got, code := verifyToken(tr, v)
			if code != "" {
				t.Fatalf("es=%v %s: reference verifier refused with %s", es, name, code)
			}
			if got.Grade != wantGrade {
				t.Fatalf("es=%v %s: grade %s", es, name, got.Grade)
			}
		}

		human, err := iss.IssueSession(peer, identity.SessionRequest{})
		if err != nil {
			t.Fatal(err)
		}
		check("human", human.Token, human.Dir, "workload")
		runtime, err := iss.IssueSession(other, identity.SessionRequest{})
		if err != nil {
			t.Fatal(err)
		}
		check("runtime", runtime.Token, runtime.Dir, "workload")
		agent, err := iss.IssueSession(peer, identity.SessionRequest{Definition: "example-builder"})
		if err != nil {
			t.Fatal(err)
		}
		check("agent", agent.Token, agent.Dir, "workload")
		// The child directory is read below by this uid, so the chain stays under it.
		child, err := iss.IssueChild(peer, identity.ChildRequest{ParentToken: agent.Token, AgentType: "example-builder", AgentID: "c1"})
		if err != nil {
			t.Fatal(err)
		}
		check("child", child.Token, child.Dir, "harness")

		// The delivery directory must satisfy the section 6 reader too.
		data, code := deliver(true, child.Dir)
		if code != "" || string(data) != child.Token {
			t.Fatalf("es=%v: delivery code %q", es, code)
		}
	}
}
