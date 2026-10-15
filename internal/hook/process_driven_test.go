//go:build linux

package hook

import (
	"errors"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// The process adapter forwards the driven origin to issue-session and still
// refuses human before any request is made.
func TestProcessAdapterAcceptsDrivenAndRefusesHuman(t *testing.T) {
	fake := newFakeIssuer(t)
	client := identity.Client{Socket: fake.Socket, Timeout: 2 * time.Second}

	line, err := ProcessAssignment(client, "example-builder", identity.OriginDriven)
	if err != nil {
		t.Fatal(err)
	}
	if want := EnvDir + "="; len(line) <= len(want) || line[:len(want)] != want {
		t.Fatalf("assignment %q", line)
	}
	reqs := fake.sessionRequests()
	if len(reqs) != 1 || reqs[0].Origin != identity.OriginDriven || reqs[0].Definition != "example-builder" {
		t.Fatalf("issue-session requests %+v", reqs)
	}

	if _, err := ProcessAssignment(client, "example-builder", "human"); !errors.Is(err, ErrOriginHuman) {
		t.Fatalf("origin human got %v", err)
	}
	if n := len(fake.sessionRequests()); n != 1 {
		t.Fatalf("human origin reached the issuer: %d requests", n)
	}
}
