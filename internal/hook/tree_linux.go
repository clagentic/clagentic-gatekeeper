//go:build linux

package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// ProcNode describes one process in the hook's ancestry. It records what the
// binding rule decides on and nothing else: the executable's identity, the
// basename of argv[0] and whether serve would treat the process as a command
// wrapper. No argument, option or value is ever recorded, because arguments can
// carry secrets.
type ProcNode struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	// Exe is the basename of the executable file; ExeID is its device and inode.
	Exe   string `json:"exe,omitempty"`
	ExeID string `json:"exe_id,omitempty"`
	// Argv0 is the basename of the first argument.
	Argv0   string `json:"argv0,omitempty"`
	Wrapper bool   `json:"wrapper,omitempty"`
}

const maxAncestry = 8

// Ancestry reads the process tree above pid from /proc, nearest first. A read
// failure ends the list; it never fails the hook.
func Ancestry(pid int) []ProcNode {
	var out []ProcNode
	for len(out) < maxAncestry && pid > 0 {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			break
		}
		s := string(stat)
		open, closing := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || closing < open {
			break
		}
		fields := strings.Fields(s[closing+1:])
		if len(fields) < 2 {
			break
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			break
		}
		node := ProcNode{PID: pid, PPID: ppid, Comm: s[open+1 : closing]}
		exePath := ""
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			exePath = strings.TrimSuffix(exe, " (deleted)")
			node.Exe = filepath.Base(exePath)
		}
		if fi, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				node.ExeID = fmt.Sprintf("%d:%d", uint64(st.Dev), st.Ino)
			}
		}
		if cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
			args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
			node.Argv0 = filepath.Base(args[0])
			// The arguments are read only to classify the process; the
			// classification is all that is kept.
			node.Wrapper = identity.IsCommandWrapper(exePath, args)
		}
		out = append(out, node)
		pid = ppid
	}
	return out
}
