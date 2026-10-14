package identity

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO opened blocking waits for a writer, which would hang the request that
// named it. Load must refuse it promptly without a writer ever appearing.
func TestDefinitionFIFORefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "example-fifo.md")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := (Definitions{Dir: dir}).Load("example-fifo")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnknownDefinition) {
			t.Fatalf("FIFO definition: got %v, want ErrUnknownDefinition", err)
		}
	case <-time.After(5 * time.Second):
		// Release the blocked open so the goroutine does not outlive the test.
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("Load blocked on a FIFO")
	}
}

func TestDefinitionDirectoryRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "example-dir.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (Definitions{Dir: dir}).Load("example-dir"); !errors.Is(err, ErrUnknownDefinition) {
		t.Fatalf("directory definition: got %v", err)
	}
}
