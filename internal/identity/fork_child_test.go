//go:build linux

package identity

import "testing"

// The runtime reports a forked subagent under the literal agent_type "fork". The
// issuer has no special case for it: the type is a definition name like any
// other, so a fork child is issued exactly when a definition of that name exists
// in the definitions directory, and is refused otherwise. It never inherits the
// parent's identity either way.
func TestForkTypedChildIsRefusedWithoutADefinitionAndIssuedWithOne(t *testing.T) {
	f := newFixture(t, nil)
	parent, parentClaims := mustSession(t, f, selfPeer(10), SessionRequest{Definition: "example-merger"})

	_, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "fork", AgentID: "a0000000000000001"})
	if ie, ok := IsIssueError(err); !ok || ie.Code != CodeDefinitionUnknown {
		t.Fatalf("fork child with no definition: %v", err)
	}

	writeDefinition(t, f.defs, "fork", "builder")
	out, err := f.issuer.IssueChild(selfPeer(10), ChildRequest{ParentToken: parent.Token, AgentType: "fork", AgentID: "a0000000000000001"})
	if err != nil {
		t.Fatalf("fork child with a definition: %v", err)
	}
	c, err := f.issuer.Keys.ParseOwn(out.Token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Act == nil || c.Act.Sub != "agent:fork" || c.Spawn != "a0000000000000001" {
		t.Fatalf("fork child claims: act %+v spawn %q", c.Act, c.Spawn)
	}
	if out.Dir == parent.Dir || out.Token == parent.Token || c.Jti == parentClaims.Jti {
		t.Fatalf("the fork child shares the parent's assertion")
	}
	for _, r := range c.Roles {
		held := false
		for _, pr := range parentClaims.Roles {
			held = held || pr == r
		}
		if !held {
			t.Fatalf("fork child role %q exceeds the parent's %v", r, parentClaims.Roles)
		}
	}
}
