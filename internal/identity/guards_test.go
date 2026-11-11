//go:build linux

package identity

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// recorder is a failer that records instead of stopping, so a test can ask a
// guard helper to fail and see that it did.
type recorder struct{ fatal, skip []string }

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(format string, args ...any) {
	r.fatal = append(r.fatal, fmt.Sprintf(format, args...))
}
func (r *recorder) Skipf(format string, args ...any) {
	r.skip = append(r.skip, fmt.Sprintf(format, args...))
}

// requireNoEntries must fail for a directory it cannot list, as well as for one
// that holds something: a listing that errors says nothing about the contents.
func TestRequireNoEntriesFailsOnAListingErrorAndOnEntries(t *testing.T) {
	empty := t.TempDir()
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "left-behind"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		dir       string
		wantFatal bool
	}{
		"an empty directory passes":      {empty, false},
		"a directory with an entry":      {full, true},
		"a directory that cannot be read": {filepath.Join(empty, "absent"), true},
	} {
		t.Run(name, func(t *testing.T) {
			var r recorder
			requireNoEntries(&r, c.dir, "case")
			if got := len(r.fatal) > 0; got != c.wantFatal {
				t.Fatalf("failed=%v, want %v: %v", got, c.wantFatal, r.fatal)
			}
		})
	}
}

// runProbe must skip, naming the precondition, for a probe that could not be
// started, and fail for a probe that started and failed.
func TestRunProbeSkipsAProbeThatCannotRunAndFailsOneThatFailed(t *testing.T) {
	var cannot recorder
	runProbe(&cannot, exec.Command(filepath.Join(t.TempDir(), "absent-binary")), "needs a runnable probe binary")
	if len(cannot.fatal) != 0 || len(cannot.skip) != 1 || !strings.Contains(cannot.skip[0], "needs a runnable probe binary") {
		t.Fatalf("a probe that could not start: fatal %v skip %v", cannot.fatal, cannot.skip)
	}

	var failed recorder
	runProbe(&failed, exec.Command(os.Args[0], "-test.no-such-flag"), "unused")
	if len(failed.skip) != 0 || len(failed.fatal) != 1 {
		t.Fatalf("a probe that ran and failed: fatal %v skip %v", failed.fatal, failed.skip)
	}

	var ran recorder
	if got := runProbe(&ran, exec.Command(os.Args[0], "-test.run=^$"), "unused"); len(ran.fatal)+len(ran.skip) != 0 || got == "" {
		t.Fatalf("a probe that ran: %q fatal %v skip %v", got, ran.fatal, ran.skip)
	}
}

// stderrWrites reports every use of os.Stderr in files outside the one function
// that is the default logger.
func stderrWrites(files []*ast.File) []string {
	var found []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				return x.Name.Name != "stderrLogf"
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "os" && x.Sel.Name == "Stderr" {
					found = append(found, "os.Stderr outside the default logger")
				}
			}
			return true
		})
	}
	return found
}

// Everything the issuer reports goes through Server.Logf, so a caller that sets
// it owns every line; the process stderr is only the default sink.
func TestOnlyTheDefaultLoggerWritesToStderr(t *testing.T) {
	files := parseSources(t, nil)
	if len(files) < 5 {
		t.Fatalf("only %d sources parsed; the walk is not reaching the package", len(files))
	}
	for _, v := range stderrWrites(files) {
		t.Error(v)
	}

	bad, err := parser.ParseFile(token.NewFileSet(), "snippet.go", "package identity\nimport (\"fmt\";\"os\")\nfunc f() { fmt.Fprintln(os.Stderr, \"x\") }", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(stderrWrites([]*ast.File{bad})) == 0 {
		t.Fatal("the guard passed a direct write to os.Stderr")
	}
}

// A stale delivery directory that cannot be removed is reported through the
// server's Logf, with the cause, and not on the process stderr.
func TestReapFailuresAreLoggedThroughLogf(t *testing.T) {
	f := newFixture(t, nil)
	old := f.issuer.Now().Add(-3 * MaxLifetimeSeconds * time.Second)
	if _, err := f.issuer.Dirs.Create(old); err != nil {
		t.Fatal(err)
	}
	f.issuer.Dirs.remove = func(int, string) error { return syscall.EPERM }

	l, err := Listen(filepath.Join(shortSocketDir(t), "s.sock"), DefaultSocketMode)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Issuer: f.issuer, Logf: f.logs.add}).Serve(ctx, l) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(f.logs.all(), "stale spawn directories remain") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("the reap failure was not logged through Logf: %q", f.logs.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A failed removal of the temporary name is part of the result, whichever way
// the publish went.
func TestPublishFileAtReportsAFailedRemovalOfItsTemporaryName(t *testing.T) {
	orig := unlinkat
	t.Cleanup(func() { unlinkat = orig })
	unlinkat = func(int, string) error { return syscall.EPERM }

	dir := t.TempDir()
	dfd := openDirFD(t, dir)
	// No-replace: the file is linked under its final name, then the second name
	// has to go; failing to remove it is an error, not silence.
	err := publishFileAt(dfd, "out", []byte("x"), 0o600, false)
	if !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), ".pub-") {
		t.Fatalf("no-replace publish with an unremovable temporary name: %v", err)
	}
	// Replace: the rename fails (an empty name is refused), and the cleanup
	// failure is reported beside that cause.
	err = publishFileAt(dfd, "", []byte("x"), 0o600, true)
	if !errors.Is(err, syscall.EPERM) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a failed publish with an unremovable temporary name: %v", err)
	}
}
