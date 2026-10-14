//go:build linux

package identity

import (
	"os"
	"testing"
)

// ReadProc reads the real /proc, which exists only on linux.
func TestReadProcOfThisProcess(t *testing.T) {
	info, err := ReadProc(int32(os.Getpid()))
	if err != nil || info.Exe == "" || info.StartTime == 0 || len(info.Args) == 0 {
		t.Fatalf("%+v %v", info, err)
	}
}
