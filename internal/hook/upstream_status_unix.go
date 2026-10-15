//go:build unix

package hook

import (
	"os"
	"syscall"
)

// endedByKill reports whether the wait status shows the process was ended by the
// SIGKILL gatekeeper sends. A process that had already exited when Kill was called
// (exited, not yet reaped) reports its own exit status here, so a Kill that
// returned nil is not taken for the cause.
func endedByKill(ps *os.ProcessState) bool {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}
