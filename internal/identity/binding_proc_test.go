//go:build linux

package identity

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParsePPIDSurvivesParenthesesInName(t *testing.T) {
	stat := "123 (we ) ird (name) S 4242 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7777 23 24"
	got, err := parsePPID(stat)
	if err != nil || got != 4242 {
		t.Fatalf("got %d %v", got, err)
	}
	if _, err := parsePPID("123 (x) S"); err == nil {
		t.Fatal("a truncated stat was accepted")
	}
}

func TestReadProcOfSelfReportsParentAndUID(t *testing.T) {
	info, err := ReadProc(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if info.PPID != int32(os.Getppid()) || !info.HasUID || info.UID != uint32(os.Geteuid()) {
		t.Fatalf("ppid=%d (want %d) uid=%d has=%v", info.PPID, os.Getppid(), info.UID, info.HasUID)
	}
}

func TestReadProcRefusesWhenParentChangesBetweenReads(t *testing.T) {
	fs := &scriptedProc{stats: []string{
		"9 (runtime) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 100 23 24",
		"9 (runtime) S 77 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 100 23 24",
	}}
	if _, err := readProcFrom(fs, 9); err == nil || !strings.Contains(err.Error(), "changed parent") {
		t.Fatalf("a reparented process was accepted: %v", err)
	}
}

const (
	bindModeEnv  = "IDENTITY_TEST_BIND_MODE"
	bindSockEnv  = "IDENTITY_TEST_BIND_SOCKET"
	bindTokenEnv = "IDENTITY_TEST_BIND_TOKEN"
)

// TestBindingHelper is the body of a client process, the stand-in for a hook.
// It is a no-op in a normal run. Modes: session (print the token), child (print
// the outcome of issue-child with the token in the environment), and runtime2
// (a second runtime that starts a child-mode client of its own).
func TestBindingHelper(t *testing.T) {
	mode := os.Getenv(bindModeEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	c := Client{Socket: os.Getenv(bindSockEnv)}
	switch mode {
	case "session":
		out, err := c.IssueSession(SessionRequest{})
		if err != nil {
			os.Stdout.WriteString("session-error:" + err.Error() + "\n")
			return
		}
		os.Stdout.WriteString("token:" + out.Token + "\n")
	case "child":
		_, err := c.IssueChild(ChildRequest{ParentToken: os.Getenv(bindTokenEnv), AgentType: "example-builder", AgentID: "hook-child"})
		if err != nil {
			os.Stdout.WriteString("child:" + err.Error() + "\n")
			return
		}
		os.Stdout.WriteString("child:issued\n")
	case "runtime2":
		cmd := exec.Command(os.Args[0], "-test.run=^TestBindingHelper$")
		cmd.Env = append(os.Environ(), bindModeEnv+"=child")
		out, err := cmd.Output()
		if err != nil {
			os.Stdout.WriteString("runtime2-error:" + err.Error() + "\n")
			return
		}
		os.Stdout.Write(out)
	}
}

func runBindingHelper(t *testing.T, sock, mode, token string, wrap bool) string {
	t.Helper()
	env := append(os.Environ(), bindSockEnv+"="+sock, bindModeEnv+"="+mode, bindTokenEnv+"="+token)
	var cmd *exec.Cmd
	if wrap {
		sh, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("no sh to act as a command wrapper")
		}
		// The trailing command keeps the shell from exec-ing the helper, so the
		// wrapper stays in the process tree.
		cmd = exec.Command(sh, "-c", `"$0" -test.run='^TestBindingHelper$'; echo done`, os.Args[0])
	} else {
		cmd = exec.Command(os.Args[0], "-test.run=^TestBindingHelper$")
	}
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper %s: %v", mode, err)
	}
	return string(out)
}

func tokenFrom(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if tok, ok := strings.CutPrefix(line, "token:"); ok {
			return tok
		}
	}
	t.Fatalf("no token in %q", out)
	return ""
}

// Real processes, real SO_PEERCRED, real /proc. The test process is the
// runtime; every client is a separate short-lived process, as hooks are.
func TestSocketHooksOfOneRuntimeShareABindingAndAnotherRuntimeIsRefused(t *testing.T) {
	c, _ := startServer(t, func(s *Settings) { s.HelperExe = os.Args[0] })

	token := tokenFrom(t, runBindingHelper(t, c.Socket, "session", "", false))

	// A later hook, a different process, is bound to the same runtime.
	if got := runBindingHelper(t, c.Socket, "child", token, false); !strings.Contains(got, "child:issued") {
		t.Fatalf("a second hook of the same runtime: %q", got)
	}
	// The same, started through a `sh -c` wrapper.
	if got := runBindingHelper(t, c.Socket, "child", token, true); !strings.Contains(got, "child:issued") {
		t.Fatalf("a hook under a command wrapper: %q", got)
	}
	// A hook whose parent is a different runtime process.
	got := runBindingHelper(t, c.Socket, "runtime2", token, false)
	if !strings.Contains(got, "child:"+CodePIDMismatch) {
		t.Fatalf("a hook under a different runtime was not refused: %q", got)
	}
}
