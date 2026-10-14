//go:build !linux

package identity

import "os/exec"

// runAsUID is never reached off linux: the tests that call it skip unless root
// can switch uid over a real SO_PEERCRED socket.
func runAsUID(*exec.Cmd, uint32) {}
