//go:build linux

package hook

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO for reading blocks until a writer appears; the definition
// reader must refuse it instead of hanging the command.
func TestReadDefinitionRefusesAFifoWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadDefinition(dir, "pipe")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
