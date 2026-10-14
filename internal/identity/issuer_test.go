package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustSession(t *testing.T, f *fixture, p Peer, req SessionRequest) (*Issued, Claims) {
	t.Helper()
	out, err := f.issuer.IssueSession(p, req)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	c, err := f.issuer.Keys.ParseOwn(out.Token)
	if err != nil {
		t.Fatal(err)
	}
	return out, c
}

func TestNonOperatorWithoutDefinitionGetsWorkloadRuntimeNeverHuman(t *testing.T) {
	f := newFixture(t, nil)
	_, c := mustSession(t, f, selfPeer(10), SessionRequest{})
	if strings.HasPrefix(c.Sub, "human:") {
		t.Fatalf("non-operator received a human subject %q", c.Sub)
	}
	if c.Act == nil || c.Act.Sub != "runtime:example-runtime" || c.Grade != "workload" {
		t.Fatalf("act=%+v grade=%s", c.Act, c.Grade)
	}
	if c.Orig == "human" {
		t.Fatal("origin human issued to a non-operator")
	}
}

func TestNonOperatorCannotClaimOriginHuman(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Origin: "human"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "origin_forbidden" {
		t.Fatalf("got %v", err)
	}
}

func TestDefinitionFileSuppliesRolesWithoutConfigEdit(t *testing.T) {
	f := newFixture(t, nil)
	_, c := mustSession(t, f, selfPeer(10), SessionRequest{Definition: "example-builder"})
	if len(c.Roles) != 1 || c.Roles[0] != "builder" {
		t.Fatalf("roles %v", c.Roles)
	}
	if c.Act == nil || c.Act.Sub != "agent:example-builder" {
		t.Fatalf("act %+v", c.Act)
	}
	// A definition added after the issuer started is picked up on the next call.
	writeDefinition(t, f.defs, "example-late", "reviewer")
	_, c = mustSession(t, f, selfPeer(10), SessionRequest{Definition: "example-late"})
	if len(c.Roles) != 1 || c.Roles[0] != "reviewer" {
		t.Fatalf("roles %v", c.Roles)
	}
}

func TestUnknownAndTraversingDefinitionsRefuse(t *testing.T) {
	f := newFixture(t, nil)
	for _, name := range []string{"does-not-exist", "../etc/passwd", "a/b", ".."} {
		_, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Definition: name})
		if ie, ok := IsIssueError(err); !ok || ie.Code != "definition_unknown" {
			t.Errorf("%q: got %v", name, err)
		}
	}
}

func TestDefinitionNameMustMatchFile(t *testing.T) {
	f := newFixture(t, nil)
	if err := os.WriteFile(filepath.Join(f.defs, "example-liar.md"), []byte("---\nname: example-other\nroles: [merger]\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Definition: "example-liar"}); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestOperatorGetsHumanUnlessRuntimeDeclared(t *testing.T) {
	op := uint32(os.Getuid())
	f := newFixture(t, func(s *Settings) { s.OperatorUID = &op })
	_, c := mustSession(t, f, selfPeer(10), SessionRequest{})
	if c.Sub != "human:example-operator" || c.Act != nil || c.Orig != "human" {
		t.Fatalf("sub=%s act=%+v origin=%s", c.Sub, c.Act, c.Orig)
	}
	_, c = mustSession(t, f, selfPeer(10), SessionRequest{Runtime: &RuntimeDecl{Version: "1.2.3"}})
	if c.Act == nil || c.Act.Sub != "runtime:example-runtime" || c.RT.Version != "1.2.3" {
		t.Fatalf("act=%+v rt=%+v", c.Act, c.RT)
	}
}

// The runtime id comes from the peer's argv, which any process of the same uid
// can set to anything. It is attribution only: no role, ceiling or
// human/workload decision may follow it.
func TestSpoofedArgvCannotChangeRolesOrGrade(t *testing.T) {
	spoofs := []struct {
		exe  string
		args []string
	}{
		{"/opt/example/example-runtime", []string{"example-runtime"}},
		{"/opt/example/example-merger", []string{"example-merger"}},
		{"/usr/bin/node", []string{"node", "example-merger.js"}},
		{"/usr/bin/python3", []string{"python3", "--", "example-builder.py"}},
		{"/usr/bin/env", []string{"env", "merger"}},
		{"/opt/example/reader", []string{"reader"}},
	}
	for _, operator := range []bool{false, true} {
		op := uint32(os.Getuid()) + 1
		if operator {
			op = uint32(os.Getuid())
		}
		f := newFixture(t, func(s *Settings) {
			s.OperatorUID = &op
			s.RuntimeRoles = []string{"reader"}
			s.OperatorRoles = []string{"operator-reader"}
		})
		var wantRoles []string
		var wantSub string
		for i, sp := range spoofs {
			exe, args := sp.exe, sp.args
			f.issuer.Proc = func(int32) (ProcInfo, error) { return ProcInfo{Exe: exe, Args: args, StartTime: 100}, nil }
			for _, req := range []SessionRequest{{}, {Runtime: &RuntimeDecl{}}} {
				_, c := mustSession(t, f, selfPeer(10), req)
				if i == 0 && req.Runtime == nil {
					wantRoles, wantSub = c.Roles, c.Sub
				}
				want := wantRoles
				if req.Runtime != nil {
					want = []string{"reader"}
				}
				// For a non-operator the subject is runtime:<rt> by design (attribution
				// only), so only the operator's subject is compared across spoofs.
				subDrifted := operator && c.Sub != wantSub
				if strings.Join(c.Roles, ",") != strings.Join(want, ",") || subDrifted {
					t.Errorf("operator=%v exe=%s args=%v req=%+v: roles %v sub %s, want roles %v sub %s", operator, exe, args, req, c.Roles, c.Sub, want, wantSub)
				}
				if !operator && (strings.HasPrefix(c.Sub, "human:") || c.Grade != "workload") {
					t.Errorf("non-operator with spoofed argv got sub %s grade %s", c.Sub, c.Grade)
				}
			}
		}
	}
}

func TestDeclaredRuntimeIdMustMatchAttested(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Runtime: &RuntimeDecl{ID: "someone-else"}})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "runtime_mismatch" {
		t.Fatalf("got %v", err)
	}
}

func TestSessionDeliveryDirectory(t *testing.T) {
	f := newFixture(t, nil)
	out, c := mustSession(t, f, selfPeer(10), SessionRequest{})
	if c.Dir != out.Dir || filepath.Dir(c.Dir) != f.root {
		t.Fatalf("dir claim %q, response %q, root %q", c.Dir, out.Dir, f.root)
	}
	fi, err := os.Stat(out.Dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(out.Dir, "tmp")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out.Dir, DeliveryFile))
	if err != nil || strings.TrimSpace(string(raw)) != out.Token {
		t.Fatalf("identity.jwt: %q %v", raw, err)
	}
	if c.Exp-c.Iat != MaxLifetimeSeconds {
		t.Fatalf("ttl %d", c.Exp-c.Iat)
	}
}

func childSetup(t *testing.T, mutate func(*Settings)) (*fixture, *Issued) {
	f := newFixture(t, mutate)
	out, _ := mustSession(t, f, selfPeer(10), SessionRequest{})
	return f, out
}

func TestChildDropsRoleOutsideDelegableAndNamesPolicy(t *testing.T) {
	f, parent := childSetup(t, func(s *Settings) { s.DelegableRoles = []string{"builder"} })
	out, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-merger", AgentID: "a1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Roles {
		if r == "merger" {
			t.Fatalf("child kept merger: %v", out.Roles)
		}
	}
	if out.Narrowed == nil || out.Narrowed.Policy != "identity.delegable_roles" || len(out.Narrowed.Dropped) != 1 || out.Narrowed.Dropped[0] != "merger" {
		t.Fatalf("narrowing %+v", out.Narrowed)
	}
}

func TestChildDefaultsToAllRolesDelegable(t *testing.T) {
	f, parent := childSetup(t, nil)
	out, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-merger", AgentID: "a1"})
	if err != nil || len(out.Roles) != 2 || out.Narrowed != nil {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestChildEmptyDelegableListDelegatesNothing(t *testing.T) {
	f, parent := childSetup(t, func(s *Settings) { s.DelegableRoles = []string{} })
	out, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "a1"})
	if err != nil || len(out.Roles) != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestChildFromOtherPidRefusesNamingMismatch(t *testing.T) {
	f, parent := childSetup(t, nil)
	_, err := f.issuer.IssueChild(selfPeer(11), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "a1"})
	ie, ok := IsIssueError(err)
	if !ok || ie.Code != "parent_pid_mismatch" || !strings.Contains(ie.Message, "pid 10") || !strings.Contains(ie.Message, "pid 11") {
		t.Fatalf("got %v", err)
	}
}

func TestChildRefusesWhenPidWasReused(t *testing.T) {
	f, parent := childSetup(t, nil)
	f.issuer.Proc = fakeProc("/opt/example/example-runtime", 999)
	_, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "a1"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "parent_pid_mismatch" {
		t.Fatalf("got %v", err)
	}
}

func TestChildRefusesExpiredAndForgedParents(t *testing.T) {
	f, parent := childSetup(t, nil)
	later := testNow.Add(f.issuer.SessionTTL)
	f.issuer.Now = func() time.Time { return later }
	_, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "a1"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "parent_expired" {
		t.Fatalf("expired: got %v", err)
	}
	f.issuer.Now = func() time.Time { return testNow }
	parts := strings.Split(parent.Token, ".")
	_, err = f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parts[0] + "." + parts[1] + ".AAAA", AgentType: "example-builder", AgentID: "a1"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "parent_invalid" {
		t.Fatalf("forged: got %v", err)
	}
}

func TestChildClaimsExtendChainAndBoundExpiry(t *testing.T) {
	f := newFixture(t, nil)
	_, parentClaims := mustSession(t, f, selfPeer(10), SessionRequest{Definition: "example-builder"})
	// Re-sign a shortened copy of the parent so the expiry bound is observable.
	parentClaims.Exp = testNow.Unix() + 600
	parentClaims.Jti = "short-parent"
	parent, err := f.issuer.Keys.SignClaims(parentClaims)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer.Registry.put("short-parent", issuedTo{pid: 10, startTime: 100, exp: parentClaims.Exp}, testNow)
	out, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent, AgentType: "example-builder", AgentID: "child-1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.issuer.Keys.ParseOwn(out.Token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Exp != parentClaims.Exp {
		t.Fatalf("child exp %d exceeds parent exp %d", c.Exp, parentClaims.Exp)
	}
	if c.Grade != "harness" || c.Spawn != "child-1" || c.Sid != parentClaims.Sid || c.Orig != "agent" || c.Dir == parentClaims.Dir {
		t.Fatalf("claims %+v", c)
	}
	if c.Act == nil || c.Act.Sub != "agent:example-builder" || c.Act.Act == nil || c.Act.Act.Sub != "agent:example-builder" {
		t.Fatalf("chain %+v", c.Act)
	}
}

func TestChildRejectsBadNames(t *testing.T) {
	f, parent := childSetup(t, nil)
	_, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "../x"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != "bad_request" {
		t.Fatalf("got %v", err)
	}
}
