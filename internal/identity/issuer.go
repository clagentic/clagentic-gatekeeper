//go:build linux

package identity

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// origins is the contract's origin vocabulary.
var origins = map[string]bool{"human": true, "scheduled": true, "loop": true, "trigger": true, "agent": true}

var reVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// Issuer turns attested peer credentials into assertions.
type Issuer struct {
	// Issuer is the iss claim.
	Issuer   string
	Keys     *Keyring
	Defs     *Definitions
	Dirs     *SpawnDirs
	Registry *Registry
	Proc     ProcReader
	Now      func() time.Time
	// HelperExe names the gatekeeper client executable. A peer running that file
	// is a transient hook or CLI process and is bound to the runtime above it
	// (bindRuntime); empty means every peer is its own runtime.
	HelperExe string

	// RuntimeRoles is the role ceiling of a session that names no definition.
	RuntimeRoles []string
	// DelegableRoles narrows issue-child. nil means every role is delegable;
	// a non-nil slice, even an empty one, restricts children to its members.
	DelegableRoles []string
	SessionTTL     time.Duration
}

// Close releases the directory handles the issuer holds.
func (i *Issuer) Close() {
	_ = i.Defs.Close()
	_ = i.Dirs.Close()
}

// Policy names reported in a Narrowing.
const (
	PolicyDelegableRoles = "identity.delegable_roles"
	PolicyParentRoles    = "parent_token.roles"
)

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

// permitted reports whether p may request issuance at all: only a peer running
// as the serving uid. It is decided from the SO_PEERCRED uid and nothing else;
// file modes on the socket are a second layer, not this check.
func (i *Issuer) permitted(p Peer) bool { return int(p.UID) == os.Geteuid() }

func (i *Issuer) refuseUnpermitted(p Peer) *IssueError {
	return refuse(http.StatusForbidden, CodePeerUIDRefused, fmt.Errorf("uid %d pid %d is not the serving uid", p.UID, p.PID))
}

// IssueSession answers issue-session for an attested peer.
func (i *Issuer) IssueSession(peer Peer, req SessionRequest) (*Issued, error) {
	if !i.permitted(peer) {
		return nil, i.refuseUnpermitted(peer)
	}
	now := i.Now()
	bound, err := i.bindRuntime(peer)
	if err != nil {
		return nil, err
	}
	rtID, err := RuntimeID(bound.Proc.Exe, bound.Proc.Args)
	if err != nil {
		return nil, refuse(http.StatusForbidden, CodePeerUnattested, err)
	}
	version := "unknown"
	if d := req.Runtime; d != nil {
		if d.ID != "" && d.ID != rtID {
			return nil, refuse(http.StatusForbidden, CodeRuntimeMismatch, fmt.Errorf("declared runtime id %q, attested %q", d.ID, rtID))
		}
		if d.Version != "" {
			if !reVersion.MatchString(d.Version) {
				return nil, refuse(http.StatusBadRequest, CodeBadRequest, fmt.Errorf("runtime version %q is not a valid version string", d.Version))
			}
			version = d.Version
		}
	}

	// No assertion is graded human by absence or by a request field: a same-uid
	// peer controls every field and its own argv, and this release has no
	// positive signal it cannot forge. Origin human is therefore never issued.
	origin := req.Origin
	switch {
	case origin == "":
		origin = "trigger"
	case !origins[origin]:
		return nil, refuse(http.StatusBadRequest, CodeBadRequest, fmt.Errorf("origin %q is not one of human, scheduled, loop, trigger, agent", origin))
	case origin == "human":
		return nil, refuse(http.StatusForbidden, CodeOriginForbidden, fmt.Errorf("origin human requested by uid %d: no human assertions are issued", peer.UID))
	}

	runtimeActor := "runtime:" + rtID
	c := Claims{Iss: i.Issuer, Sub: runtimeActor, Grade: "workload", RT: Runtime{ID: rtID, Version: version}, Orig: origin}

	switch {
	case req.Definition != "":
		def, err := i.Defs.Load(req.Definition)
		if err != nil {
			return nil, refuse(http.StatusNotFound, CodeDefinitionUnknown, err)
		}
		c.Roles = def.Roles
		c.Act = &Actor{Sub: "agent:" + def.Name}
	default:
		c.Roles = i.RuntimeRoles
		c.Act = &Actor{Sub: runtimeActor}
	}

	return i.finish(peer, bound, c, now, now.Add(i.SessionTTL), nil)
}

// IssueChild answers issue-child for an attested peer.
func (i *Issuer) IssueChild(peer Peer, req ChildRequest) (*Issued, error) {
	if !i.permitted(peer) {
		return nil, i.refuseUnpermitted(peer)
	}
	// One clock sample serves the parent expiry check and the child's iat, so
	// crossing the parent's exp mid-request cannot yield a child that outlives it.
	now := i.Now()
	if !reName.MatchString(req.AgentType) || !reName.MatchString(req.AgentID) {
		return nil, refuse(http.StatusBadRequest, CodeBadRequest, fmt.Errorf("agent_type and agent_id must match %s", reName))
	}
	parent, err := i.Keys.ParseOwn(req.ParentToken)
	if err != nil {
		return nil, refuse(http.StatusForbidden, CodeParentInvalid, err)
	}
	if parent.Exp <= now.Unix() {
		return nil, refuse(http.StatusForbidden, CodeParentExpired, fmt.Errorf("the parent token expired at %d", parent.Exp))
	}
	issued, ok := i.Registry.get(parent.Jti)
	if !ok {
		return nil, refuse(http.StatusForbidden, CodeParentUnknown, fmt.Errorf("jti %q is not in this process's registry", parent.Jti))
	}
	if issued.uid != peer.UID {
		return nil, refuse(http.StatusForbidden, CodeUIDMismatch, fmt.Errorf("the parent token was issued to uid %d, the request comes from uid %d", issued.uid, peer.UID))
	}
	bound, err := i.bindRuntime(peer)
	if err != nil {
		return nil, err
	}
	proc := bound.Proc
	if issued.pid != bound.PID {
		return nil, refuse(http.StatusForbidden, CodePIDMismatch, fmt.Errorf("the parent token was issued to runtime pid %d, the request is bound to runtime pid %d (peer pid %d)", issued.pid, bound.PID, peer.PID))
	}
	if proc.StartTime != issued.startTime {
		return nil, refuse(http.StatusForbidden, CodePIDMismatch, fmt.Errorf("pid %d is no longer the process the parent token was issued to (start time differs)", bound.PID))
	}
	if proc.ExeDev != issued.exeDev || proc.ExeIno != issued.exeIno {
		return nil, refuse(http.StatusForbidden, CodeExeMismatch, fmt.Errorf("pid %d runs a different executable file than at issue time (dev/inode %d/%d, was %d/%d)", bound.PID, proc.ExeDev, proc.ExeIno, issued.exeDev, issued.exeIno))
	}
	def, err := i.Defs.Load(req.AgentType)
	if err != nil {
		return nil, refuse(http.StatusNotFound, CodeDefinitionUnknown, err)
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
	return i.finish(peer, bound, child, now, exp, narrowed)
}

// finish allocates the delivery directory, signs, publishes and records. now
// is the caller's single clock sample; finish never reads the clock itself. The
// assertion is recorded against the bound runtime, not the requesting process.
func (i *Issuer) finish(peer Peer, bound Binding, c Claims, now, exp time.Time, narrowed *Narrowing) (*Issued, error) {
	if now.Unix() >= exp.Unix() {
		return nil, refuse(http.StatusForbidden, CodeLifetimeEmpty, nil)
	}
	jti, err := randomID()
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, CodeInternal, err)
	}
	if c.Sid == "" {
		sid, err := randomID()
		if err != nil {
			return nil, refuse(http.StatusInternalServerError, CodeInternal, err)
		}
		c.Sid = "s-" + sid
	}
	if c.Roles == nil {
		c.Roles = []string{}
	}
	c.Iat, c.Exp, c.Jti, c.Cia = now.Unix(), exp.Unix(), jti, ContractVersion

	dir, err := i.Dirs.Create(now)
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, CodeSpawnDir, err)
	}
	c.Dir = filepath.Clean(dir)
	token, err := i.Keys.SignClaims(c)
	if err == nil {
		err = i.Dirs.Publish(dir, peer, token)
	}
	if err != nil {
		_ = i.Dirs.Discard(dir)
		return nil, refuse(http.StatusInternalServerError, CodeInternal, err)
	}
	i.Registry.put(jti, issuedTo{uid: peer.UID, pid: bound.PID, startTime: bound.Proc.StartTime, exeDev: bound.Proc.ExeDev, exeIno: bound.Proc.ExeIno, exp: c.Exp}, now)

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
