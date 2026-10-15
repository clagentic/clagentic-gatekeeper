//go:build !unix && !windows

package hook

import "os"

// endedByKill on a GOOS with neither signal statuses nor a known termination
// code can only trust that Kill succeeded.
func endedByKill(*os.ProcessState) bool { return true }
