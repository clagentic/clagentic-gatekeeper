//go:build linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
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
	// ExeDev and ExeIno identify the executable file the process is running.
	// A process that exec-replaces itself keeps its pid and start time but gets
	// a different file here.
	ExeDev, ExeIno uint64
	// PPID is the parent pid the kernel reported, bracketed like StartTime.
	PPID int32
	// UID is the effective uid of the process. HasUID is false when the reader
	// could not supply it; ancestry binding treats that as a refusal.
	UID    uint32
	HasUID bool
}

// ProcReader reads ProcInfo for a pid; the default reads /proc.
type ProcReader func(pid int32) (ProcInfo, error)

// procFiles is the part of /proc ReadProc touches, so a test can make a
// process change or vanish between two reads.
type procFiles interface {
	readlink(pid int32, name string) (string, error)
	readFile(pid int32, name string) ([]byte, error)
	// exeIdentity returns the device and inode of the file /proc/<pid>/exe
	// resolves to.
	exeIdentity(pid int32) (dev, ino uint64, err error)
}

type realProc struct{}

func (realProc) path(pid int32, name string) string {
	return filepath.Join("/proc", strconv.Itoa(int(pid)), name)
}

func (r realProc) readlink(pid int32, name string) (string, error) {
	return os.Readlink(r.path(pid, name))
}

func (r realProc) readFile(pid int32, name string) ([]byte, error) {
	return os.ReadFile(r.path(pid, name))
}

// uidOf reads the effective uid from /proc/<pid>/status. The owner of the
// /proc/<pid> directory is not used because it is root for a non-dumpable
// process whatever uid it runs as.
func (r realProc) uidOf(pid int32) (uint32, error) {
	raw, err := os.ReadFile(r.path(pid, "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			break
		}
		n, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(n), nil
	}
	return 0, errors.New("no Uid line in /proc status")
}

func (r realProc) exeIdentity(pid int32) (uint64, uint64, error) {
	fi, err := os.Stat(r.path(pid, "exe"))
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("no device and inode for the executable")
	}
	return uint64(st.Dev), st.Ino, nil
}

// ReadProc is the /proc based ProcReader.
func ReadProc(pid int32) (ProcInfo, error) { return readProcFrom(realProc{}, pid) }

// uidSource is implemented by a procFiles that can report the effective uid.
// It is separate so the base interface, and every fake of it, is unchanged.
type uidSource interface {
	uidOf(pid int32) (uint32, error)
}

// Nothing read here may decide a grant: roles, grade, human versus workload and
// directory ownership follow the SO_PEERCRED uid. /proc feeds attribution, the
// binding of an assertion to its runtime process (bindRuntime) and a start-time
// comparison, and any failure to read it is a refusal.
//
// readProcFrom reads the start time before and after exe and cmdline. The
// separate /proc reads are not atomic, so a peer that exits mid-read and whose
// pid is reused would otherwise yield an exe from one process and a start time
// from another; the same start time on both sides proves one process answered
// every read, and a vanished pid fails a read outright. The parent pid is
// bracketed the same way, so a parent that exits mid-read (and reparents the
// process) is refused rather than read half old, half new.
func readProcFrom(fs procFiles, pid int32) (ProcInfo, error) {
	before, beforePPID, err := statOf(fs, pid)
	if err != nil {
		return ProcInfo{}, err
	}
	exe, err := fs.readlink(pid, "exe")
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read exe of pid %d (the issuer needs ptrace access to peers of other uids): %w", pid, err)
	}
	dev, ino, err := fs.exeIdentity(pid)
	if err != nil {
		return ProcInfo{}, fmt.Errorf("identify exe of pid %d: %w", pid, err)
	}
	cmdline, err := fs.readFile(pid, "cmdline")
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read cmdline of pid %d: %w", pid, err)
	}
	var uid uint32
	hasUID := false
	if us, ok := fs.(uidSource); ok {
		if uid, err = us.uidOf(pid); err != nil {
			return ProcInfo{}, fmt.Errorf("read uid of pid %d: %w", pid, err)
		}
		hasUID = true
	}
	after, afterPPID, err := statOf(fs, pid)
	if err != nil {
		return ProcInfo{}, err
	}
	if before != after {
		return ProcInfo{}, fmt.Errorf("pid %d changed process while it was being read (start time %d then %d)", pid, before, after)
	}
	if beforePPID != afterPPID {
		return ProcInfo{}, fmt.Errorf("pid %d changed parent while it was being read (ppid %d then %d)", pid, beforePPID, afterPPID)
	}
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	return ProcInfo{
		Exe: strings.TrimSuffix(exe, " (deleted)"), Args: args, StartTime: before, ExeDev: dev, ExeIno: ino,
		PPID: beforePPID, UID: uid, HasUID: hasUID,
	}, nil
}

func statOf(fs procFiles, pid int32) (start uint64, ppid int32, err error) {
	stat, err := fs.readFile(pid, "stat")
	if err != nil {
		return 0, 0, fmt.Errorf("read stat of pid %d: %w", pid, err)
	}
	if start, err = parseStartTime(string(stat)); err != nil {
		return 0, 0, err
	}
	if ppid, err = parsePPID(string(stat)); err != nil {
		return 0, 0, err
	}
	return start, ppid, nil
}

// parsePPID extracts field 4 of /proc/<pid>/stat, counted from the last ')'
// for the reason parseStartTime gives.
func parsePPID(stat string) (int32, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("malformed /proc stat")
	}
	fields := strings.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 4 is fields[1].
	if len(fields) < 2 {
		return 0, errors.New("malformed /proc stat")
	}
	n, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return 0, errors.New("malformed /proc stat")
	}
	return int32(n), nil
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
