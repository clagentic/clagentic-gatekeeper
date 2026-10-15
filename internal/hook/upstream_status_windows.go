//go:build windows

package hook

import "os"

// killExitCode is the exit code os.Process.Kill gives the process it terminates.
const killExitCode = 1

// endedByKill reports whether the wait status is the one Kill leaves. Windows has
// no signal death: a terminated process reports the code it was terminated with.
// Kill fails on a process that had already exited, so a Kill that succeeded and
// left this code is the cause.
func endedByKill(ps *os.ProcessState) bool {
	return ps.ExitCode() == killExitCode
}
