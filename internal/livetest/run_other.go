//go:build !linux

package livetest

import (
	"context"
	"io"
)

// Exit codes of Run.
const (
	ExitOK          = 0
	ExitFailed      = 1
	ExitInterrupted = 130
)

// Run reports that nothing can run here: the issuer and the runtime binding it
// is tested through rely on SO_PEERCRED and /proc and exist on linux only.
func Run(_ context.Context, _ Options, out io.Writer) int {
	rep := NewReporter(out)
	rep.Add(Result{Shape: "all", Status: Skip, Reason: "the issuer and the runtime binding are linux-only"})
	rep.Summary()
	return ExitOK
}
