//go:build linux

package identity

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// maxWrapperHops bounds how many `sh -c` wrappers may sit between the gatekeeper
// client and the runtime that owns the session.
const maxWrapperHops = 3

// shellNames are the executables treated as a command-string wrapper. Only a
// shell started with -c qualifies (see isCommandWrapper).
var shellNames = regexp.MustCompile(`^(sh|bash|dash|ash|zsh|ksh|mksh|busybox)$`)

// shortFlagWithC matches a short-option cluster that includes c, such as -c, -lc
// or -ec: the shell runs a later argument as a command string.
var shortFlagWithC = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

// isCommandWrapper reports whether p is a shell running a command string. A
// shell running a script file, or an interactive one, is a program in its own
// right and is never skipped. Only the leading option arguments are inspected,
// so text inside the command string cannot make a shell look like a wrapper.
func isCommandWrapper(p ProcInfo) bool {
	if !shellNames.MatchString(baseName(p.Exe)) {
		return false
	}
	for _, a := range p.Args[min(1, len(p.Args)):] {
		switch {
		case shortFlagWithC.MatchString(a):
			return true
		case strings.HasPrefix(a, "-"):
			continue
		default:
			return false
		}
	}
	return false
}

// IsCommandWrapper reports whether a process with this executable and argument
// vector is a shell running a command string, by the same rule serve applies
// when it climbs to the runtime.
func IsCommandWrapper(exe string, args []string) bool {
	return isCommandWrapper(ProcInfo{Exe: exe, Args: args})
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Binding is the process an assertion is bound to: the runtime that owns the
// session, never the transient client process that made the request.
type Binding struct {
	PID  int32
	Proc ProcInfo
}

// isHelper reports whether p runs the gatekeeper client executable named by
// HelperExe. The file is resolved at each call so an in-place upgrade of the
// binary does not strand hooks started from the new file.
func (i *Issuer) isHelper(p ProcInfo) bool {
	if i.HelperExe == "" {
		return false
	}
	fi, err := os.Stat(i.HelperExe)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return p.ExeDev == uint64(st.Dev) && p.ExeIno == st.Ino
}

func unbound(detail error) *IssueError {
	return refuse(http.StatusForbidden, CodeRuntimeUnbound, detail)
}

// confirm re-reads a process and refuses when it is no longer the one first
// read, which brackets every record used for a binding by its start time.
func (i *Issuer) confirm(pid int32, first ProcInfo) error {
	again, err := i.Proc(pid)
	if err != nil {
		return refuse(http.StatusForbidden, CodePeerUnattested, err)
	}
	if again.StartTime != first.StartTime || again.PPID != first.PPID || again.ExeDev != first.ExeDev || again.ExeIno != first.ExeIno {
		return unbound(errors.New("the process ancestry changed while it was being read"))
	}
	return nil
}

// bindRuntime returns the process an issuance for peer binds to.
//
// A peer that is not the gatekeeper client binary is its own runtime: a direct
// client of the socket is the long-lived process that owns its session.
//
// A peer that is the gatekeeper client binary (a hook or the CLI) is a transient
// helper by construction. Its runtime is found by climbing the kernel's parent
// chain, and only the kernel's: the pid comes from SO_PEERCRED and every step is
// the ppid /proc reports for the previous process, so nothing in the request can
// name, steer or extend the walk. The rule:
//
//   - the first ancestor is the peer's parent;
//   - an ancestor that is a shell running a command string (sh -c ...) is a
//     wrapper the runtime used to start the hook, and is climbed through, at most
//     maxWrapperHops times;
//   - the first ancestor that is not such a wrapper is the runtime;
//   - the peer itself, on either path, and every ancestor must run as the peer's uid, must not be younger than the
//     process below it, and must not be init (pid 1) or the pid 0 an orphan
//     reports;
//   - each process is read bracketed by its start time and parent pid, and the
//     whole chain is re-read after the walk and must be identical, so a process
//     that exited and was replaced mid-walk is refused.
//
// Any /proc failure or a violated condition refuses; there is no fallback to the
// peer itself, because that would bind the assertion to a process that exits
// before the next hook runs.
func (i *Issuer) bindRuntime(peer Peer) (Binding, error) {
	first, err := i.Proc(peer.PID)
	if err != nil {
		return Binding{}, refuse(http.StatusForbidden, CodePeerUnattested, err)
	}
	if !first.HasUID || first.UID != peer.UID {
		return Binding{}, unbound(fmt.Errorf("peer pid %d does not run as the uid the socket attested", peer.PID))
	}
	if !i.isHelper(first) {
		if err := i.confirm(peer.PID, first); err != nil {
			return Binding{}, err
		}
		return Binding{PID: peer.PID, Proc: first}, nil
	}

	type link struct {
		pid  int32
		proc ProcInfo
	}
	chain := []link{{peer.PID, first}}
	for hops := 0; ; hops++ {
		below := chain[len(chain)-1]
		ppid := below.proc.PPID
		if ppid <= 1 {
			return Binding{}, unbound(fmt.Errorf("pid %d has parent %d: no runtime above it", below.pid, ppid))
		}
		parent, err := i.Proc(ppid)
		if err != nil {
			return Binding{}, refuse(http.StatusForbidden, CodePeerUnattested, err)
		}
		if !parent.HasUID || parent.UID != peer.UID {
			return Binding{}, unbound(fmt.Errorf("ancestor pid %d does not run as uid %d", ppid, peer.UID))
		}
		if parent.StartTime > below.proc.StartTime {
			return Binding{}, unbound(fmt.Errorf("ancestor pid %d started after pid %d, which a parent cannot", ppid, below.pid))
		}
		chain = append(chain, link{ppid, parent})
		if !isCommandWrapper(parent) {
			break
		}
		if hops >= maxWrapperHops {
			return Binding{}, unbound(fmt.Errorf("more than %d command wrappers above pid %d", maxWrapperHops, peer.PID))
		}
	}

	for _, l := range chain {
		if err := i.confirm(l.pid, l.proc); err != nil {
			return Binding{}, err
		}
	}
	rt := chain[len(chain)-1]
	return Binding{PID: rt.pid, Proc: rt.proc}, nil
}
