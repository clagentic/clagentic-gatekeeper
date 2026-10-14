package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write refused") }

func TestPrintIssuedReportsAFailedWrite(t *testing.T) {
	out := &identity.Issued{Token: "t"}
	for _, asJSON := range []bool{false, true} {
		if err := printIssued(failingWriter{}, out, asJSON); err == nil {
			t.Errorf("json=%v: a failed write was reported as success", asJSON)
		}
	}
}

func TestPrintIssuedWritesTheBareToken(t *testing.T) {
	var b strings.Builder
	if err := printIssued(&b, &identity.Issued{Token: "abc"}, false); err != nil || b.String() != "abc\n" {
		t.Fatalf("%q, %v", b.String(), err)
	}
}

func TestReportNarrowingReportsAFailedWrite(t *testing.T) {
	out := &identity.Issued{Narrowed: &identity.Narrowing{Steps: []identity.PolicyStep{{Policy: "p", Dropped: []string{"r"}}}}}
	if err := reportNarrowing(failingWriter{}, out); err == nil {
		t.Fatal("a failed write was reported as success")
	}
	if err := reportNarrowing(failingWriter{}, &identity.Issued{}); err != nil {
		t.Fatalf("nothing to write, yet: %v", err)
	}
}
