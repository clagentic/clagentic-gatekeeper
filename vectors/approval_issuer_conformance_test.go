//go:build linux

package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// An approval the issuer signs must pass the same reference verifier that
// proves the published vectors, with either key type, and nothing the verifier
// reads may come from the request.
func TestIssuedApprovalsPassConformance(t *testing.T) {
	for _, es := range []bool{false, true} {
		dir := t.TempDir()
		defs := filepath.Join(dir, "defs")
		if err := os.Mkdir(defs, 0o755); err != nil {
			t.Fatal(err)
		}
		iss, err := identity.NewIssuer(identity.Settings{
			SocketPath: filepath.Join(dir, "run", "identity.sock"), KeyPath: issuerKey(t, dir, es),
			DefinitionsDir: defs, SpawnRoot: filepath.Join(dir, "spawn"),
			Approver: "example-operator", ApprovalTTL: 120 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer iss.Close()
		peer := identity.Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), PID: int32(os.Getpid())}

		sess, err := iss.IssueSession(peer, identity.SessionRequest{})
		if err != nil {
			t.Fatal(err)
		}
		pending, err := iss.RequestApproval(peer, identity.ApprovalRequest{Token: sess.Token, Op: approvalOp, ParamsDigest: approvalPD})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := iss.GrantApproval(peer, identity.ApprovalGrantRequest{Token: sess.Token, Rid: pending.Rid}); err != nil {
			t.Fatal(err)
		}
		got, err := iss.FetchApproval(peer, identity.ApprovalFetchRequest{Rid: pending.Rid})
		if err != nil {
			t.Fatal(err)
		}

		raw, err := iss.Keys.MarshalJWKS()
		if err != nil {
			t.Fatal(err)
		}
		var doc jwksDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		tr := trust{iss.Issuer: doc}
		v := approvalVector{Token: got.Approval, Now: time.Now().Unix(), ExpectedOp: approvalOp, ExpectedPD: approvalPD}
		claims, code := verifyApproval(tr, v)
		if code != "" {
			t.Fatalf("es=%v: the reference verifier refused with %s", es, code)
		}
		sessClaims := claimsOfToken(t, sess.Token)
		if claims["sid"] != sessClaims["sid"] || claims["acked_by"] != "example-operator" || claims["rid"] != pending.Rid {
			t.Fatalf("es=%v: claims %v, session %v", es, claims, sessClaims)
		}
		// The two artifacts are told apart by the header alone.
		if hdr, _ := decodeObject(strings.Split(sess.Token, ".")[0]); hdr["typ"] != nil {
			t.Fatalf("es=%v: the identity assertion header carries typ %v", es, hdr["typ"])
		}
		if _, code := verifyApproval(tr, approvalVector{Token: sess.Token, Now: time.Now().Unix(), ExpectedOp: approvalOp, ExpectedPD: approvalPD}); code != "approval_typ_invalid" {
			t.Fatalf("es=%v: an identity assertion read as an approval: %q", es, code)
		}
		// The verifier also refuses what the consumer did not ask for.
		if _, code := verifyApproval(tr, approvalVector{Token: got.Approval, Now: time.Now().Unix(), ExpectedOp: "example.other", ExpectedPD: approvalPD}); code != "approval_op_mismatch" {
			t.Fatalf("es=%v: another op: %q", es, code)
		}
	}
}

// claimsOfToken decodes a token's payload without verifying it.
func claimsOfToken(t *testing.T, token string) map[string]any {
	t.Helper()
	c, ok := decodeObject(strings.Split(token, ".")[1])
	if !ok {
		t.Fatalf("bad payload in %q", token)
	}
	return c
}
