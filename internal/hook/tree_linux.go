//go:build linux

package hook

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcNode describes one process in the hook's ancestry. Only names and option
// flags are recorded, never an argument value, because arguments can carry
// secrets.
type ProcNode struct {
	PID   int      `json:"pid"`
	PPID  int      `json:"ppid"`
	Comm  string   `json:"comm"`
	Exe   string   `json:"exe,omitempty"`
	Flags []string `json:"flags,omitempty"`
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
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			node.Exe = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		}
		if cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
			args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
			for _, a := range args[min(1, len(args)):] {
				if !strings.HasPrefix(a, "-") || len(node.Flags) == 4 {
					break
				}
				if strings.Contains(a, "=") {
					a = a[:strings.IndexByte(a, '=')]
				}
				node.Flags = append(node.Flags, a)
			}
		}
		out = append(out, node)
		pid = ppid
	}
	return out
}
