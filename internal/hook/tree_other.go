//go:build !linux

package hook

// ProcNode describes one process in the hook's ancestry. Ancestry is read from
// /proc, which exists only on linux, where the issuer also runs.
type ProcNode struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe,omitempty"`
	ExeID   string `json:"exe_id,omitempty"`
	Argv0   string `json:"argv0,omitempty"`
	Wrapper bool   `json:"wrapper,omitempty"`
}

// Ancestry reports nothing off linux.
func Ancestry(int) []ProcNode { return nil }
