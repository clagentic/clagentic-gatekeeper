//go:build linux

package identity

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func openDirFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

func TestPublishFileAtReplacesAndLeavesNoTemporaryName(t *testing.T) {
	dir := t.TempDir()
	dfd := openDirFD(t, dir)
	for _, body := range []string{"first", "second"} {
		if err := publishFileAt(dfd, "out", []byte(body), 0o644, true); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "out"))
	if err != nil || string(got) != "second" {
		t.Fatalf("content %q, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("entries after publish: %v", entries)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "out")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestPublishFileAtWithoutReplaceKeepsAnExistingEntry(t *testing.T) {
	old := syscall.Umask(0o77)
	defer syscall.Umask(old)
	dir := t.TempDir()
	dfd := openDirFD(t, dir)
	if err := publishFileAt(dfd, "out", []byte("mine"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	err := publishFileAt(dfd, "out", []byte("other"), 0o600, false)
	if !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("got %v, want EEXIST", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "out"))
	if string(got) != "mine" {
		t.Fatalf("an existing entry was overwritten: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a refused publish left entries: %v", entries)
	}
}

func TestPublishFileAtDoesNotFollowALinkedFinalName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	dfd := openDirFD(t, dir)
	if err := publishFileAt(dfd, "out", []byte("x"), 0o600, false); err == nil {
		t.Fatal("published over a symlink without replace")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("the link target was created")
	}
}

// Class guard: a file serve writes becomes visible under its final name only
// through publishFileAt, which flushes before and after the rename. A second
// create or rename site would bypass that.
func TestOnlyPublishFileAtCreatesOrRenames(t *testing.T) {
	banned := map[string]bool{
		"syscall.Renameat": true, "syscall.Rename": true, "os.Rename": true,
		"syscall.O_CREAT": true, "os.WriteFile": true, "os.Create": true, "os.OpenFile": true,
		"os.CreateTemp": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "publish_linux.go" {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		ast.Inspect(f, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && banned[pkg.Name+"."+sel.Sel.Name] {
				t.Errorf("%s: %s.%s outside publish_linux.go; publish through publishFileAt", fset.Position(sel.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if seen < 5 {
		t.Fatalf("only %d sources scanned; the walk is not reaching the package", seen)
	}
}
