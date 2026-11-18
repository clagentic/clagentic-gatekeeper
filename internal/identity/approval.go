//go:build linux

package identity

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// maxApprovalOpBytes and maxApprovalSummaryBytes bound what a request can
	// make the issuer hold and log.
	maxApprovalOpBytes      = 128
	maxApprovalSummaryBytes = 512
	// approvalRetain is how long an entry outlives its expiry, so a late caller
	// is told the approval expired rather than that it never existed.
	approvalRetain = 10 * time.Minute
)

var (
	reApprovalOp  = regexp.MustCompile(`^[A-Za-z0-9._:/@+-]{1,128}$`)
	reApprovalPD  = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	reApprovalRid = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// reApproverName is the shape of the configured approver name, which becomes
	// the acked_by claim.
	reApproverName = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,128}$`)
)

// approvalEntry is one request. It is pending until granted, then holds the
// signed approval until the first fetch.
type approvalEntry struct {
	sid, op, pd string
	reqExp      int64
	signed      string
	grantExp    int64
	fetched     bool
}

func (e *approvalEntry) granted() bool { return e.signed != "" || e.fetched }

// lapse is the instant after which nothing about the entry can still be used.
func (e *approvalEntry) lapse() int64 { return max(e.reqExp, e.grantExp) }

// Approvals is the in-memory store of operator approvals. Like the registry it
// is deliberately not persisted: a restart drops every pending request, which
// costs the operator one new request and keeps an approval from outliving the
// process that vouched for it.
type Approvals struct {
	approver string
	ttl      time.Duration

	mu      sync.Mutex
	entries map[string]*approvalEntry
}

// NewApprovals returns a store that signs approvals acked by approver for ttl
// each. A ttl of zero means the maximum.
func NewApprovals(approver string, ttl time.Duration) (*Approvals, error) {
	if !reApproverName.MatchString(approver) {
		return nil, fmt.Errorf("identity.approval.approver %q must match %s", approver, reApproverName)
	}
	if ttl == 0 {
		ttl = MaxApprovalTTLSeconds * time.Second
	}
	if ttl < time.Second || ttl > MaxApprovalTTLSeconds*time.Second {
		return nil, fmt.Errorf("identity.approval.ttl_seconds must be between 1 and %d", MaxApprovalTTLSeconds)
	}
	return &Approvals{approver: approver, ttl: ttl, entries: map[string]*approvalEntry{}}, nil
}

// purge drops entries that lapsed more than approvalRetain ago. The caller
// holds the lock.
func (a *Approvals) purge(now time.Time) {
	for rid, e := range a.entries {
		if e.lapse()+int64(approvalRetain/time.Second) < now.Unix() {
			delete(a.entries, rid)
		}
	}
}

// sessionRefusals are the holder refusals that mean "this assertion cannot be
// accepted"; an approval operation reports them under its own code.
var sessionRefusals = map[string]bool{
	CodeParentInvalid: true, CodeParentExpired: true, CodeParentUnknown: true,
	CodeUIDMismatch: true, CodePIDMismatch: true, CodeExeMismatch: true,
}

// approvalHolder is holder with the approval namespace on the refusals that
// would otherwise talk about a parent token. Refusals about the peer itself
// keep their identity code.
func (i *Issuer) approvalHolder(peer Peer, token string, now time.Time) (Claims, error) {
	c, _, err := i.holder(peer, token, now)
	if err != nil {
		if ie, ok := IsIssueError(err); ok && sessionRefusals[ie.Code] {
			return Claims{}, refuse(http.StatusForbidden, CodeApprovalSession, ie)
		}
		return Claims{}, err
	}
	return c, nil
}

// approvalReady is the check every approval operation starts with.
func (i *Issuer) approvalReady(peer Peer) error {
	if !i.permitted(peer) {
		return i.refuseUnpermitted(peer)
	}
	if i.Approvals == nil {
		return refuse(http.StatusForbidden, CodeApprovalOff, nil)
	}
	return nil
}

// RequestApproval records a pending approval for one operation, bound to the
// caller's session, the operation name and the digest of its parameters.
func (i *Issuer) RequestApproval(peer Peer, req ApprovalRequest) (*ApprovalPending, error) {
	if err := i.approvalReady(peer); err != nil {
		return nil, err
	}
	if !reApprovalOp.MatchString(req.Op) {
		return nil, refuse(http.StatusBadRequest, CodeApprovalOp, fmt.Errorf("op %q", req.Op))
	}
	if !reApprovalPD.MatchString(req.ParamsDigest) {
		return nil, refuse(http.StatusBadRequest, CodeApprovalDigest, errors.New("params_digest is not 64 hex characters"))
	}
	if len(req.Summary) > maxApprovalSummaryBytes || !utf8.ValidString(req.Summary) || strings.ContainsFunc(req.Summary, isControl) {
		return nil, refuse(http.StatusBadRequest, CodeBadRequest, errors.New("summary is too long, not UTF-8 or holds control characters"))
	}
	now := i.Now()
	session, err := i.approvalHolder(peer, req.Token, now)
	if err != nil {
		return nil, err
	}
	rid, err := randomID()
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, CodeInternal, err)
	}
	a := i.Approvals
	exp := now.Add(a.ttl).Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	a.entries[rid] = &approvalEntry{sid: session.Sid, op: req.Op, pd: strings.ToLower(req.ParamsDigest), reqExp: exp}
	return &ApprovalPending{Rid: rid, ExpiresAt: exp, Phrase: ApprovalPhrasePrefix + rid}, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// GrantApproval signs the approval for a pending request. Only the session the
// request was made in can grant it, and only while it is pending and unexpired.
// Whether the operator typed the phrase is the caller's to establish; the
// issuer binds the grant to the session and nothing more.
func (i *Issuer) GrantApproval(peer Peer, req ApprovalGrantRequest) (*ApprovalGranted, error) {
	if err := i.approvalReady(peer); err != nil {
		return nil, err
	}
	now := i.Now()
	session, err := i.approvalHolder(peer, req.Token, now)
	if err != nil {
		return nil, err
	}
	a := i.Approvals
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	e, ok := a.entries[req.Rid]
	switch {
	case !ok || !reApprovalRid.MatchString(req.Rid):
		return nil, refuse(http.StatusNotFound, CodeApprovalUnknown, fmt.Errorf("rid %q", req.Rid))
	case e.sid != session.Sid:
		return nil, refuse(http.StatusForbidden, CodeApprovalSessionMismatch, fmt.Errorf("rid %s was requested in session %s, the grant comes from session %s", req.Rid, e.sid, session.Sid))
	case e.granted():
		return nil, refuse(http.StatusConflict, CodeApprovalAlreadyGranted, fmt.Errorf("rid %s", req.Rid))
	case e.reqExp <= now.Unix():
		return nil, refuse(http.StatusGone, CodeApprovalExpired, fmt.Errorf("rid %s expired at %d", req.Rid, e.reqExp))
	}
	exp := now.Add(a.ttl).Unix()
	signed, err := i.Keys.SignApproval(ApprovalClaims{
		Iss: i.Issuer, Rid: req.Rid, Op: e.op, PD: e.pd, Sid: e.sid, AckedBy: a.approver,
		Iat: now.Unix(), Exp: exp, Cap: 1,
	})
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, CodeInternal, err)
	}
	e.signed, e.grantExp = signed, exp
	return &ApprovalGranted{Rid: req.Rid, ExpiresAt: exp}, nil
}

// FetchApproval returns the signed approval of a granted request, once, to any
// caller the issuer admits. No parentage is checked: whoever fetches it first
// uses it, and it names the one operation and parameters it approves.
func (i *Issuer) FetchApproval(peer Peer, req ApprovalFetchRequest) (*ApprovalFetched, error) {
	if err := i.approvalReady(peer); err != nil {
		return nil, err
	}
	now := i.Now()
	a := i.Approvals
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	e, ok := a.entries[req.Rid]
	switch {
	case !ok || !reApprovalRid.MatchString(req.Rid):
		return nil, refuse(http.StatusNotFound, CodeApprovalUnknown, fmt.Errorf("rid %q", req.Rid))
	case e.fetched:
		return nil, refuse(http.StatusConflict, CodeApprovalAlreadyFetched, fmt.Errorf("rid %s", req.Rid))
	case !e.granted():
		if e.reqExp <= now.Unix() {
			return nil, refuse(http.StatusGone, CodeApprovalExpired, fmt.Errorf("rid %s expired at %d unfetched and ungranted", req.Rid, e.reqExp))
		}
		return nil, refuse(http.StatusConflict, CodeApprovalNotGranted, fmt.Errorf("rid %s", req.Rid))
	case e.grantExp <= now.Unix():
		return nil, refuse(http.StatusGone, CodeApprovalExpired, fmt.Errorf("rid %s expired at %d", req.Rid, e.grantExp))
	}
	signed := e.signed
	e.signed, e.fetched = "", true
	return &ApprovalFetched{Rid: req.Rid, Approval: signed, ExpiresAt: e.grantExp}, nil
}
