package identity

import (
	"os/exec"
	"syscall"
)

// runAsUID makes cmd start under uid and gid uid. SysProcAttr.Credential has
// no counterpart off linux, which is why this sits behind a build tag.
func runAsUID(cmd *exec.Cmd, uid uint32) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
}
