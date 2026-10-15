//go:build unix

package hook

import (
	"os/exec"
	"testing"
	"time"
)

// A Kill that returns nil on a process that had already exited is not proof it
// caused the exit: the wait status says the process ended on its own.
func TestKillOfAnExitedUnreapedProcessIsNotTakenForTheCause(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // exited, not reaped: Wait has not run
	if err := cmd.Process.Kill(); err != nil {
		t.Skipf("this platform refuses Kill on an unreaped process: %v", err)
	}
	_ = cmd.Wait()
	if endedByKill(cmd.ProcessState) || cmd.ProcessState.ExitCode() != 7 {
		t.Fatalf("exit %d taken for a kill", cmd.ProcessState.ExitCode())
	}
}

func TestKilledProcessIsShownByItsWaitStatus(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !endedByKill(cmd.ProcessState) {
		t.Fatal("a killed process was not shown as killed")
	}
}
