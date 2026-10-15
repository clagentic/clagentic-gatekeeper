//go:build linux

package identity

import (
	"strings"
	"testing"
)

// A launcher obtains a workload assertion for a session a human drives; the
// assertion carries the new origin under contract major 2 and no human.
func TestDrivenOriginIssuesWorkloadAssertionUnderMajor2(t *testing.T) {
	f := newFixture(t, func(s *Settings) { s.RuntimeRoles = []string{"reader"} })
	for _, def := range []string{"", "example-builder"} {
		out, c := mustSession(t, f, selfPeer(10), SessionRequest{Origin: OriginDriven, Definition: def})
		if c.Orig != OriginDriven || c.Cia != ContractVersionDriven {
			t.Fatalf("definition %q: origin %q cia %d", def, c.Orig, c.Cia)
		}
		if c.Grade != "workload" || out.Grade != "workload" || strings.HasPrefix(c.Sub, "human:") || strings.HasPrefix(out.Subject, "human:") {
			t.Fatalf("definition %q: grade %s sub %s", def, c.Grade, c.Sub)
		}
		child, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: out.Token, AgentType: "example-builder", AgentID: "d1"})
		if err != nil {
			t.Fatal(err)
		}
		cc, err := f.issuer.Keys.ParseOwn(child.Token)
		if err != nil {
			t.Fatal(err)
		}
		if cc.Orig != "agent" || cc.Cia != ContractVersion || cc.Grade != "harness" {
			t.Fatalf("child of a driven session: origin %q cia %d grade %s", cc.Orig, cc.Cia, cc.Grade)
		}
	}
}

// No level of the act chain of an issued driven session names a human, and
// finish refuses to sign one that does, at any depth.
func TestDrivenActChainNeverNamesHuman(t *testing.T) {
	f := newFixture(t, nil)
	for _, def := range []string{"", "example-builder"} {
		_, c := mustSession(t, f, selfPeer(10), SessionRequest{Origin: OriginDriven, Definition: def})
		if actorChainNamesHuman(c.Act) {
			t.Fatalf("definition %q: issued act chain names a human: %+v", def, c.Act)
		}
	}
	chains := map[string]*Actor{
		"depth 1": {Sub: "human:example-user"},
		"depth 2": {Sub: "agent:example-builder", Act: &Actor{Sub: "human:example-user"}},
		"depth 3": {Sub: "agent:example-builder", Act: &Actor{Sub: "runtime:example-runtime", Act: &Actor{Sub: "human:example-user"}}},
	}
	now := f.issuer.Now()
	for name, act := range chains {
		c := Claims{Iss: f.issuer.Issuer, Sub: "runtime:example-runtime", Grade: "workload", Orig: OriginDriven, Act: act}
		_, err := f.issuer.finish(selfPeer(10), Binding{}, c, now, now.Add(f.issuer.SessionTTL), nil)
		if ie, ok := IsIssueError(err); !ok || ie.Code != CodeInternal {
			t.Errorf("%s: finish got %v, want %s", name, err, CodeInternal)
		}
	}
}

// Every origin a major 1 consumer already reads keeps cia 1, so the new value
// changes nothing for them.
func TestOtherOriginsKeepMajor1(t *testing.T) {
	f := newFixture(t, nil)
	for _, o := range []string{"", "scheduled", "loop", "trigger", "agent"} {
		_, c := mustSession(t, f, selfPeer(10), SessionRequest{Origin: o})
		if c.Cia != ContractVersion {
			t.Errorf("origin %q: cia %d", o, c.Cia)
		}
	}
}

// Origin human stays refused for session issuance, and an unknown origin still
// names driven in its refusal.
func TestHumanStillRefusedWithDrivenAvailable(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Origin: "human"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != CodeOriginForbidden {
		t.Fatalf("origin human got %v", err)
	}
	_, err = f.issuer.IssueSession(selfPeer(10), SessionRequest{Origin: "interactive"})
	ie, ok := IsIssueError(err)
	if !ok || ie.Code != CodeBadRequest {
		t.Fatalf("unknown origin got %v", err)
	}
}
