package identity

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"time"
)

// IssueError is a refusal with a stable code and message a client can act on.
// detail holds the internal cause (paths, keys, parser and host errors); it is
// logged by the server and never serialised or included in Error. It is
// unexported so no package-level caller can read it; Unwrap is the in-process
// route for errors.Is/As.
type IssueError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	detail  error
}

func (e *IssueError) Error() string { return e.Code + ": " + e.Message }

// Unwrap exposes the internal cause to errors.Is/As in-process only.
func (e *IssueError) Unwrap() error { return e.detail }

func refuse(status int, code, format string, args ...any) *IssueError {
	return &IssueError{Code: code, Message: fmt.Sprintf(format, args...), Status: status}
}

// refuseInternal answers with a fixed public message and keeps cause for the
// server log, so a client never learns filesystem, key, parser or host
// details.
func refuseInternal(status int, code, message string, cause error) *IssueError {
	return &IssueError{Code: code, Message: message, Status: status, detail: cause}
}

const (
	publicInternalMessage = "the issuer failed to complete the request; see the issuer log"
	publicUninspectable   = "the calling process could not be inspected"
	publicParentInvalid   = "the parent token is not a valid assertion issued by this server"
)

// unknownDefinition hides why a definition failed to load (paths, parse
// errors); the caller only learns that the name is not usable.
func unknownDefinition(name string, cause error) *IssueError {
	return refuseInternal(http.StatusNotFound, "definition_unknown", fmt.Sprintf("definition %q is not available", name), cause)
}

// origins is the contract's origin vocabulary.
var origins = map[string]bool{"human": true, "scheduled": true, "loop": true, "trigger": true, "agent": true}

var reVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// Issuer turns attested peer credentials into assertions.
type Issuer struct {
	// Issuer is the iss claim.
	Issuer   string
	Keys     *Keyring
	Defs     Definitions
	Dirs     SpawnDirs
	Registry *Registry
	Proc     ProcReader
	Now      func() time.Time

	// OperatorUID is the only uid that may receive a human subject; nil means
	// none may.
	OperatorUID  *uint32
	OperatorName string
	// OperatorRoles and RuntimeRoles are the role ceilings of sessions that
	// name no definition.
	OperatorRoles []string
	RuntimeRoles  []string
	// DelegableRoles narrows issue-child. nil means every role is delegable;
	// a non-nil slice, even an empty one, restricts children to its members.
	DelegableRoles []string
	SessionTTL     time.Duration
}

// RuntimeDecl is a client's statement that it is a runtime session. The id is
// optional and, when given, must equal the attested one.
type RuntimeDecl struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

// SessionRequest is the body of issue-session.
type SessionRequest struct {
	Definition string       `json:"definition,omitempty"`
	Origin     string       `json:"origin,omitempty"`
	Runtime    *RuntimeDecl `json:"runtime,omitempty"`
}

// ChildRequest is the body of issue-child.
type ChildRequest struct {
	ParentToken string `json:"parent_token"`
	AgentType   string `json:"agent_type"`
	AgentID     string `json:"agent_id"`
}

// Policy names reported in a Narrowing.
const (
	PolicyDelegableRoles = "identity.delegable_roles"
	PolicyParentRoles    = "parent_token.roles"
)

// PolicyStep is the roles one policy removed.
type PolicyStep struct {
	Policy  string   `json:"policy"`
	Dropped []string `json:"dropped"`
}

// Narrowing reports every policy that removed roles from a requested set.
// Policy and Dropped summarise all steps (policy names joined by a comma,
// dropped roles in order); Steps lists each policy with its own drops.
type Narrowing struct {
	Policy  string       `json:"policy"`
	Dropped []string     `json:"dropped"`
	Steps   []PolicyStep `json:"steps"`
}

// add records a policy's drops; it returns n unchanged when nothing was
// dropped and allocates on first use, so a nil Narrowing means no narrowing.
func (n *Narrowing) add(policy string, dropped []string) *Narrowing {
	if len(dropped) == 0 {
		return n
	}
	if n == nil {
		n = &Narrowing{Dropped: []string{}}
	} else {
		n.Policy += ","
	}
	n.Policy += policy
	n.Dropped = append(n.Dropped, dropped...)
	n.Steps = append(n.Steps, PolicyStep{Policy: policy, Dropped: dropped})
	return n
}

// Issued is the response of both operations.
type Issued struct {
	Token     string     `json:"token"`
	Dir       string     `json:"dir"`
	ExpiresAt int64      `json:"expires_at"`
	Subject   string     `json:"sub"`
	Actor     string     `json:"actor"`
	Grade     string     `json:"grade"`
	Roles     []string   `json:"roles"`
	Narrowed  *Narrowing `json:"narrowed,omitempty"`
}

func (i *Issuer) isOperator(p Peer) bool { return i.OperatorUID != nil && *i.OperatorUID == p.UID }

// IssueSession answers issue-session for an attested peer.
func (i *Issuer) IssueSession(peer Peer, req SessionRequest) (*Issued, error) {
	now := i.Now()
	proc, err := i.Proc(peer.PID)
	if err != nil {
		return nil, refuseInternal(http.StatusForbidden, "peer_unattested", publicUninspectable, err)
	}
	rtID, err := RuntimeID(proc.Exe, proc.Args)
	if err != nil {
		return nil, refuseInternal(http.StatusForbidden, "peer_unattested", "no runtime id can be derived from the calling process", err)
	}
	version := "unknown"
	if d := req.Runtime; d != nil {
		if d.ID != "" && d.ID != rtID {
			return nil, refuse(http.StatusForbidden, "runtime_mismatch", "declared runtime id %q does not match the attested runtime %q", d.ID, rtID)
		}
		if d.Version != "" {
			if !reVersion.MatchString(d.Version) {
				return nil, refuse(http.StatusBadRequest, "bad_request", "runtime version %q is not a valid version string", d.Version)
			}
			version = d.Version
		}
	}

	operator := i.isOperator(peer)
	origin := req.Origin
	switch {
	case origin == "":
		origin = "trigger"
		if operator {
			origin = "human"
		}
	case !origins[origin]:
		return nil, refuse(http.StatusBadRequest, "bad_request", "origin %q is not one of human, scheduled, loop, trigger, agent", origin)
	case origin == "human" && !operator:
		return nil, refuse(http.StatusForbidden, "origin_forbidden", "origin human is only issued to the operator uid")
	}

	runtimeActor := "runtime:" + rtID
	c := Claims{Iss: i.Issuer, Grade: "workload", RT: Runtime{ID: rtID, Version: version}, Orig: origin}
	c.Sub = runtimeActor
	if operator {
		c.Sub = "human:" + i.OperatorName
	}

	switch {
	case req.Definition != "":
		def, err := i.Defs.Load(req.Definition)
		if err != nil {
			return nil, unknownDefinition(req.Definition, err)
		}
		c.Roles = def.Roles
		c.Act = &Actor{Sub: "agent:" + def.Name}
	case operator && req.Runtime == nil:
		c.Roles = i.OperatorRoles
	default:
		c.Roles = i.RuntimeRoles
		c.Act = &Actor{Sub: runtimeActor}
	}

	return i.finish(peer, proc, c, now, now.Add(i.SessionTTL), nil)
}

// IssueChild answers issue-child for an attested peer.
func (i *Issuer) IssueChild(peer Peer, req ChildRequest) (*Issued, error) {
	// One clock sample serves the parent expiry check and the child's iat, so
	// crossing the parent's exp mid-request cannot yield a child that outlives it.
	now := i.Now()
	if !reName.MatchString(req.AgentType) || !reName.MatchString(req.AgentID) {
		return nil, refuse(http.StatusBadRequest, "bad_request", "agent_type and agent_id must match [A-Za-z0-9._-]{1,128}")
	}
	parent, err := i.Keys.ParseOwn(req.ParentToken)
	if err != nil {
		return nil, refuseInternal(http.StatusForbidden, "parent_invalid", publicParentInvalid, err)
	}
	if parent.Exp <= now.Unix() {
		return nil, refuse(http.StatusForbidden, "parent_expired", "the parent token expired at %d", parent.Exp)
	}
	issued, ok := i.Registry.get(parent.Jti)
	if !ok {
		return nil, refuse(http.StatusForbidden, "parent_unknown", "the parent token was not issued by this serve process; ask for a new session")
	}
	if issued.uid != peer.UID {
		return nil, refuse(http.StatusForbidden, "uid_mismatch", "the parent token was issued to uid %d but this request comes from uid %d", issued.uid, peer.UID)
	}
	if issued.pid != peer.PID {
		return nil, refuse(http.StatusForbidden, "parent_pid_mismatch", "the parent token was issued to pid %d but this request comes from pid %d", issued.pid, peer.PID)
	}
	proc, err := i.Proc(peer.PID)
	if err != nil {
		return nil, refuseInternal(http.StatusForbidden, "peer_unattested", publicUninspectable, err)
	}
	if proc.StartTime != issued.startTime {
		return nil, refuse(http.StatusForbidden, "parent_pid_mismatch", "pid %d is no longer the process the parent token was issued to (start time differs)", peer.PID)
	}
	def, err := i.Defs.Load(req.AgentType)
	if err != nil {
		return nil, unknownDefinition(req.AgentType, err)
	}

	// Delegation never widens: the child holds the definition's roles that the
	// deployment allows to be delegated and that the parent itself holds. The
	// parent bound is always applied; an empty parent set is a policy, not an
	// absent one.
	parentRoles := parent.Roles
	if parentRoles == nil {
		parentRoles = []string{}
	}
	roles, narrowed := def.Roles, (*Narrowing)(nil)
	for _, step := range []struct {
		policy string
		allow  []string
	}{
		{PolicyDelegableRoles, i.DelegableRoles},
		{PolicyParentRoles, parentRoles},
	} {
		var dropped []string
		roles, dropped = intersect(roles, step.allow)
		narrowed = narrowed.add(step.policy, dropped)
	}
	child := Claims{
		Iss: i.Issuer, Sub: parent.Sub, Roles: roles, Grade: "harness", RT: parent.RT,
		Sid: parent.Sid, Spawn: req.AgentID, Orig: "agent",
		Act: &Actor{Sub: "agent:" + def.Name, Act: parent.Act},
	}
	exp := now.Add(i.SessionTTL)
	if pe := time.Unix(parent.Exp, 0); pe.Before(exp) {
		exp = pe
	}
	return i.finish(peer, proc, child, now, exp, narrowed)
}

// finish allocates the delivery directory, signs, publishes and records. now
// is the caller's single clock sample; finish never reads the clock itself.
func (i *Issuer) finish(peer Peer, proc ProcInfo, c Claims, now, exp time.Time, narrowed *Narrowing) (*Issued, error) {
	if now.Unix() >= exp.Unix() {
		return nil, refuse(http.StatusForbidden, "lifetime_empty", "the assertion would not outlive its issue time")
	}
	jti, err := randomID()
	if err != nil {
		return nil, refuseInternal(http.StatusInternalServerError, "internal", publicInternalMessage, err)
	}
	if c.Sid == "" {
		sid, err := randomID()
		if err != nil {
			return nil, refuseInternal(http.StatusInternalServerError, "internal", publicInternalMessage, err)
		}
		c.Sid = "s-" + sid
	}
	if c.Roles == nil {
		c.Roles = []string{}
	}
	c.Iat, c.Exp, c.Jti, c.Cia = now.Unix(), exp.Unix(), jti, ContractVersion

	dir, err := i.Dirs.Create()
	if err != nil {
		return nil, refuseInternal(http.StatusInternalServerError, "spawn_dir", "could not prepare a delivery directory; see the issuer log", err)
	}
	c.Dir = filepath.Clean(dir)
	token, err := i.Keys.SignClaims(c)
	if err == nil {
		err = i.Dirs.Publish(dir, peer, token)
	}
	if err != nil {
		_ = i.Dirs.Discard(dir)
		return nil, refuseInternal(http.StatusInternalServerError, "internal", publicInternalMessage, err)
	}
	i.Registry.put(jti, issuedTo{uid: peer.UID, pid: peer.PID, startTime: proc.StartTime, exp: c.Exp}, now)

	actor := c.Sub
	if c.Act != nil {
		actor = c.Act.Sub
	}
	return &Issued{Token: token, Dir: c.Dir, ExpiresAt: c.Exp, Subject: c.Sub, Actor: actor, Grade: c.Grade, Roles: c.Roles, Narrowed: narrowed}, nil
}

// intersect returns the members of want that policy allows, and the ones it
// removed. A nil policy allows everything.
func intersect(want, policy []string) (kept, dropped []string) {
	kept, dropped = []string{}, []string{}
	if policy == nil {
		return append(kept, want...), dropped
	}
	allowed := map[string]bool{}
	for _, r := range policy {
		allowed[r] = true
	}
	for _, r := range want {
		if allowed[r] {
			kept = append(kept, r)
		} else {
			dropped = append(dropped, r)
		}
	}
	return kept, dropped
}

// IsIssueError extracts an *IssueError from err.
func IsIssueError(err error) (*IssueError, bool) {
	var ie *IssueError
	ok := errors.As(err, &ie)
	return ie, ok
}
