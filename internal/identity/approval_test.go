//go:build linux

package identity

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testApprover = "example-operator"
	testDigest   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testOp       = "example.run-command"
)

// approvalFixture is an issuer with operator approval on and one session.
func approvalFixture(t *testing.T, mutate func(*Settings)) (*fixture, *Issued) {
	t.Helper()
	f := newFixture(t, func(s *Settings) {
		s.Approver = testApprover
		if mutate != nil {
			mutate(s)
		}
	})
	sess, _ := mustSession(t, f, selfPeer(10), SessionRequest{})
	return f, sess
}

// parseApproval verifies an approval's signature against the issuer's key set
// and returns its header and claims.
func parseApproval(t *testing.T, k *Keyring, token string) (map[string]any, ApprovalClaims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	var hdr map[string]any
	if err := decodeSegment(parts[0], &hdr); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := hdr["kid"].(string)
	alg, _ := hdr["alg"].(string)
	if !k.verify(kid, alg, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatalf("the approval signature does not verify against the published key set")
	}
	var c ApprovalClaims
	if err := decodeSegment(parts[1], &c); err != nil {
		t.Fatal(err)
	}
	return hdr, c
}

func wantApprovalCode(t *testing.T, name string, err error, code string) {
	t.Helper()
	ie, ok := IsIssueError(err)
	switch {
	case code == "" && err != nil:
		t.Errorf("%s: refused: %v", name, err)
	case code != "" && (!ok || ie.Code != code):
		t.Errorf("%s: got %v, want code %s", name, err, code)
	case code != "" && ie.Message != publicMessages[code]:
		t.Errorf("%s: message %q is not the code's one message", name, ie.Message)
	}
}

func TestApprovalRequest(t *testing.T) {
	longSummary := strings.Repeat("x", maxApprovalSummaryBytes+1)
	for _, tc := range []struct {
		name string
		req  func(token string) ApprovalRequest
		off  bool
		code string
	}{
		{"valid", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: testDigest, Summary: "run the example command"}
		}, false,""},
		{"upper-case digest is accepted", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: strings.ToUpper(testDigest)}
		}, false,""},
		{"short digest", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: testDigest[:63]}
		}, false,CodeApprovalDigest},
		{"non-hex digest", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: strings.Repeat("g", 64)}
		}, false,CodeApprovalDigest},
		{"empty op", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, ParamsDigest: testDigest}
		}, false,CodeApprovalOp},
		{"op with a space", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: "two words", ParamsDigest: testDigest}
		}, false,CodeApprovalOp},
		{"no approver configured", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: testDigest}
		}, true, CodeApprovalOff},
		{"summary over the bound", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: testDigest, Summary: longSummary}
		}, false,CodeBadRequest},
		{"summary with a control character", func(tok string) ApprovalRequest {
			return ApprovalRequest{Token: tok, Op: testOp, ParamsDigest: testDigest, Summary: "a\nb"}
		}, false,CodeBadRequest},
		{"token that is not an assertion", func(string) ApprovalRequest {
			return ApprovalRequest{Token: "not.a.token", Op: testOp, ParamsDigest: testDigest}
		}, false,CodeApprovalSession},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, sess := approvalFixture(t, func(s *Settings) {
				if tc.off {
					s.Approver = ""
				}
			})
			out, err := f.issuer.RequestApproval(selfPeer(10), tc.req(sess.Token))
			wantApprovalCode(t, tc.name, err, tc.code)
			if tc.code != "" {
				return
			}
			if len(out.Rid) != 32 || out.Phrase != "approve "+out.Rid {
				t.Fatalf("rid %q phrase %q", out.Rid, out.Phrase)
			}
			if got := out.ExpiresAt - testNow.Unix(); got <= 0 || got > MaxApprovalTTLSeconds {
				t.Fatalf("expires in %ds, want 1..%d", got, MaxApprovalTTLSeconds)
			}
		})
	}
}

// A request from a runtime other than the one the session belongs to, or from
// another uid, is refused like every other operation of the issuer.
func TestApprovalRequestFromAnotherRuntimeOrUID(t *testing.T) {
	f, sess := approvalFixture(t, nil)
	_, err := f.issuer.RequestApproval(selfPeer(11), ApprovalRequest{Token: sess.Token, Op: testOp, ParamsDigest: testDigest})
	wantApprovalCode(t, "another pid", err, CodeApprovalSession)
	other := selfPeer(10)
	other.UID++
	_, err = f.issuer.RequestApproval(other, ApprovalRequest{Token: sess.Token, Op: testOp, ParamsDigest: testDigest})
	wantApprovalCode(t, "another uid", err, CodePeerUIDRefused)
}

func TestApprovalGrantAndFetch(t *testing.T) {
	type env struct {
		f      *fixture
		sess   *Issued
		other  *Issued
		rid    string
		now    time.Time
		grant  func(token, rid string) error
		fetch  func(rid string) (*ApprovalFetched, error)
		setNow func(time.Time)
	}
	setup := func(t *testing.T) *env {
		t.Helper()
		f, sess := approvalFixture(t, func(s *Settings) { s.ApprovalTTL = 60 * time.Second })
		other, _ := mustSession(t, f, selfPeer(11), SessionRequest{})
		e := &env{f: f, sess: sess, other: other, now: testNow}
		f.issuer.Now = func() time.Time { return e.now }
		pending, err := f.issuer.RequestApproval(selfPeer(10), ApprovalRequest{Token: sess.Token, Op: testOp, ParamsDigest: testDigest})
		if err != nil {
			t.Fatal(err)
		}
		e.rid = pending.Rid
		e.grant = func(token, rid string) error {
			// A token issued to pid 11 is presented by pid 11, as a real session is.
			peer := selfPeer(10)
			if token == other.Token {
				peer = selfPeer(11)
			}
			_, err := f.issuer.GrantApproval(peer, ApprovalGrantRequest{Token: token, Rid: rid})
			return err
		}
		e.fetch = func(rid string) (*ApprovalFetched, error) {
			return f.issuer.FetchApproval(selfPeer(12), ApprovalFetchRequest{Rid: rid})
		}
		e.setNow = func(n time.Time) { e.now = n }
		return e
	}

	t.Run("grant", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			run  func(e *env) error
			code string
		}{
			{"pending, same session", func(e *env) error { return e.grant(e.sess.Token, e.rid) }, ""},
			{"bound to another session", func(e *env) error { return e.grant(e.other.Token, e.rid) }, CodeApprovalSessionMismatch},
			{"unknown rid", func(e *env) error { return e.grant(e.sess.Token, strings.Repeat("0", 32)) }, CodeApprovalUnknown},
			{"malformed rid", func(e *env) error { return e.grant(e.sess.Token, "approve") }, CodeApprovalUnknown},
			{"expired", func(e *env) error {
				e.setNow(e.now.Add(61 * time.Second))
				return e.grant(e.sess.Token, e.rid)
			}, CodeApprovalExpired},
			{"already granted", func(e *env) error {
				if err := e.grant(e.sess.Token, e.rid); err != nil {
					return err
				}
				return e.grant(e.sess.Token, e.rid)
			}, CodeApprovalAlreadyGranted},
			{"granted and fetched", func(e *env) error {
				if err := e.grant(e.sess.Token, e.rid); err != nil {
					return err
				}
				if _, err := e.fetch(e.rid); err != nil {
					return err
				}
				return e.grant(e.sess.Token, e.rid)
			}, CodeApprovalAlreadyGranted},
			{"token that is not an assertion", func(e *env) error { return e.grant("not.a.token", e.rid) }, CodeApprovalSession},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wantApprovalCode(t, tc.name, tc.run(setup(t)), tc.code)
			})
		}
	})

	t.Run("fetch", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			run  func(e *env) error
			code string
		}{
			{"granted, first fetch", func(e *env) error {
				if err := e.grant(e.sess.Token, e.rid); err != nil {
					return err
				}
				_, err := e.fetch(e.rid)
				return err
			}, ""},
			{"second fetch", func(e *env) error {
				if err := e.grant(e.sess.Token, e.rid); err != nil {
					return err
				}
				if _, err := e.fetch(e.rid); err != nil {
					return err
				}
				_, err := e.fetch(e.rid)
				return err
			}, CodeApprovalAlreadyFetched},
			{"before the grant", func(e *env) error { _, err := e.fetch(e.rid); return err }, CodeApprovalNotGranted},
			{"after the approval expired", func(e *env) error {
				if err := e.grant(e.sess.Token, e.rid); err != nil {
					return err
				}
				e.setNow(e.now.Add(61 * time.Second))
				_, err := e.fetch(e.rid)
				return err
			}, CodeApprovalExpired},
			{"never granted, request expired", func(e *env) error {
				e.setNow(e.now.Add(61 * time.Second))
				_, err := e.fetch(e.rid)
				return err
			}, CodeApprovalExpired},
			{"unknown rid", func(e *env) error { _, err := e.fetch(strings.Repeat("1", 32)); return err }, CodeApprovalUnknown},
			{"long after expiry the entry is gone", func(e *env) error {
				e.setNow(e.now.Add(time.Hour))
				_, err := e.fetch(e.rid)
				return err
			}, CodeApprovalUnknown},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wantApprovalCode(t, tc.name, tc.run(setup(t)), tc.code)
			})
		}
	})

	// The approval itself: typ, claims, signature, and that nothing in it came
	// from the request or the prompt.
	t.Run("the signed approval", func(t *testing.T) {
		e := setup(t)
		if err := e.grant(e.sess.Token, e.rid); err != nil {
			t.Fatal(err)
		}
		got, err := e.fetch(e.rid)
		if err != nil {
			t.Fatal(err)
		}
		hdr, c := parseApproval(t, e.f.issuer.Keys, got.Approval)
		if hdr["typ"] != ApprovalTyp || hdr["kid"] != e.f.issuer.Keys.Kid() || hdr["alg"] != e.f.issuer.Keys.Alg() {
			t.Fatalf("header %v", hdr)
		}
		sessClaims, err := e.f.issuer.Keys.ParseOwn(e.sess.Token)
		if err != nil {
			t.Fatal(err)
		}
		want := ApprovalClaims{
			Iss: e.f.issuer.Issuer, Rid: e.rid, Op: testOp, PD: testDigest, Sid: sessClaims.Sid,
			AckedBy: testApprover, Iat: testNow.Unix(), Exp: testNow.Unix() + 60, Cap: 1,
		}
		if c != want {
			t.Fatalf("claims %+v, want %+v", c, want)
		}
		if got.ExpiresAt != want.Exp || got.Rid != e.rid {
			t.Fatalf("fetch reply %+v", got)
		}
		// The assertion the approval sits beside carries no typ, so a verifier can
		// tell the two apart by the header alone.
		var aHdr map[string]any
		if err := decodeSegment(strings.Split(e.sess.Token, ".")[0], &aHdr); err != nil || aHdr["typ"] != nil {
			t.Fatalf("assertion header %v %v", aHdr, err)
		}
		// An approval is never accepted where an assertion is read: its claims do
		// not carry the assertion's required members.
		raw, _ := json.Marshal(c)
		if strings.Contains(string(raw), `"roles"`) || strings.Contains(string(raw), `"cia"`) {
			t.Fatalf("approval claims %s look like an assertion", raw)
		}
	})
}

func TestApprovalIsOffWithoutAnApprover(t *testing.T) {
	f := newFixture(t, nil)
	sess, _ := mustSession(t, f, selfPeer(10), SessionRequest{})
	_, err := f.issuer.RequestApproval(selfPeer(10), ApprovalRequest{Token: sess.Token, Op: testOp, ParamsDigest: testDigest})
	wantApprovalCode(t, "request", err, CodeApprovalOff)
	_, err = f.issuer.GrantApproval(selfPeer(10), ApprovalGrantRequest{Token: sess.Token, Rid: strings.Repeat("a", 32)})
	wantApprovalCode(t, "grant", err, CodeApprovalOff)
	_, err = f.issuer.FetchApproval(selfPeer(10), ApprovalFetchRequest{Rid: strings.Repeat("a", 32)})
	wantApprovalCode(t, "fetch", err, CodeApprovalOff)
}

func TestNewApprovalsRefusesWhatItCannotSign(t *testing.T) {
	for _, tc := range []struct {
		name     string
		approver string
		ttl      time.Duration
		ok       bool
	}{
		{"default ttl", testApprover, 0, true},
		{"maximum ttl", testApprover, 300 * time.Second, true},
		{"over the maximum", testApprover, 301 * time.Second, false},
		{"under a second", testApprover, time.Millisecond, false},
		{"approver with a space", "two words", 0, false},
		{"empty approver", "", 0, false},
		{"approver over 128", strings.Repeat("a", 129), 0, false},
	} {
		_, err := NewApprovals(tc.approver, tc.ttl)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// The whole path over the real socket, with the real /proc and SO_PEERCRED: a
// session requests, the same session grants, another process fetches, and the
// approval verifies against the published key set.
func TestApprovalOverTheSocket(t *testing.T) {
	c, f := startServer(t, func(s *Settings) { s.Approver = testApprover })
	sess, err := c.IssueSession(SessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := c.RequestApproval(ApprovalRequest{Token: sess.Token, Op: testOp, ParamsDigest: testDigest, Summary: "run it"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.FetchApproval(ApprovalFetchRequest{Rid: pending.Rid}); !hasCode(err, CodeApprovalNotGranted) {
		t.Fatalf("fetch before grant: %v", err)
	}
	if _, err := c.GrantApproval(ApprovalGrantRequest{Token: sess.Token, Rid: pending.Rid}); err != nil {
		t.Fatal(err)
	}
	got, err := c.FetchApproval(ApprovalFetchRequest{Rid: pending.Rid})
	if err != nil {
		t.Fatal(err)
	}
	_, claims := parseApproval(t, f.issuer.Keys, got.Approval)
	sessClaims, err := f.issuer.Keys.ParseOwn(sess.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sid != sessClaims.Sid || claims.Op != testOp || claims.PD != testDigest || claims.AckedBy != testApprover {
		t.Fatalf("claims %+v", claims)
	}
	if _, err := c.FetchApproval(ApprovalFetchRequest{Rid: pending.Rid}); !hasCode(err, CodeApprovalAlreadyFetched) {
		t.Fatalf("second fetch: %v", err)
	}
	// A refusal carries the code's one message and never the detail.
	if _, err := c.RequestApproval(ApprovalRequest{Token: sess.Token, Op: "", ParamsDigest: testDigest}); !hasCode(err, CodeApprovalOp) {
		t.Fatalf("empty op: %v", err)
	}
	logs := f.logs.all()
	for _, want := range []string{"approval requested rid=" + pending.Rid, "approval granted rid=" + pending.Rid, "approval fetched rid=" + pending.Rid, `summary="run it"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log lacks %q:\n%s", want, logs)
		}
	}
	// A body with a member the operation does not know is not run.
	if status, body := post(t, c, PathApprovalRequest, `{"token":"x","op":"a","params_digest":"b","acked_by":"someone"}`); status != 400 || !strings.Contains(body, `"error":"bad_request"`) {
		t.Fatalf("unknown member: %d %s", status, body)
	}
}

func hasCode(err error, code string) bool {
	ie, ok := IsIssueError(err)
	return ok && ie.Code == code
}
