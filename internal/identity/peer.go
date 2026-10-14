package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Peer is the kernel-attested identity of the process on the other end of the
// socket (SO_PEERCRED). It is read from the accepted connection, never from
// the request.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// ProcInfo is what /proc reveals about a peer process.
type ProcInfo struct {
	Exe  string
	Args []string
	// StartTime is the process start in clock ticks since boot. Together with
	// the pid it identifies one process even after the pid is reused.
	StartTime uint64
}

// ProcReader reads ProcInfo for a pid; the default reads /proc.
type ProcReader func(pid int32) (ProcInfo, error)

// ReadProc is the /proc based ProcReader.
func ReadProc(pid int32) (ProcInfo, error) {
	base := filepath.Join("/proc", strconv.Itoa(int(pid)))
	exe, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read exe of pid %d (the issuer needs ptrace access to peers of other uids): %w", pid, err)
	}
	cmdline, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read cmdline of pid %d: %w", pid, err)
	}
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read stat of pid %d: %w", pid, err)
	}
	start, err := parseStartTime(string(stat))
	if err != nil {
		return ProcInfo{}, err
	}
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	return ProcInfo{Exe: strings.TrimSuffix(exe, " (deleted)"), Args: args, StartTime: start}, nil
}

// parseStartTime extracts field 22 of /proc/<pid>/stat. The command name is
// parenthesised and may itself contain spaces or parentheses, so fields are
// counted from the last ')'.
func parseStartTime(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("malformed /proc stat")
	}
	fields := strings.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, errors.New("malformed /proc stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// interpreters run a script; the script, not the interpreter, names the runtime.
var interpreters = regexp.MustCompile(`^(node|nodejs|bun|deno|python|python[0-9.]+|ruby|perl|php|java|bash|sh|dash|zsh|env)$`)

var (
	reUnsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	reHasAlnum   = regexp.MustCompile(`[A-Za-z0-9]`)
)

// RuntimeID derives the runtime id from the peer's executable and command
// line: the executable's base name, or for an interpreter the first script
// argument's base name without its extension.
func RuntimeID(exe string, args []string) (string, error) {
	name := filepath.Base(exe)
	if interpreters.MatchString(name) {
		for _, a := range args[min(1, len(args)):] {
			if a == "" || strings.HasPrefix(a, "-") {
				continue
			}
			name = strings.TrimSuffix(filepath.Base(a), filepath.Ext(a))
			break
		}
	}
	name = reUnsafeName.ReplaceAllString(name, "-")
	if len(name) > 128 {
		name = name[:128]
	}
	if !reName.MatchString(name) || !reHasAlnum.MatchString(name) {
		return "", fmt.Errorf("cannot derive a runtime id from executable %q", exe)
	}
	return name, nil
}
