//go:build linux

package identity

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parsePackageSources(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", n), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}

// publicCodes returns the value of every Code* constant the package exports.
func publicCodes(t *testing.T) map[string]string {
	t.Helper()
	codes := map[string]string{}
	for _, f := range parsePackageSources(t) {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, "Code") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						t.Fatalf("%s is not a string literal", n.Name)
					}
					codes[n.Name] = strings.Trim(lit.Value, `"`)
				}
			}
		}
	}
	if len(codes) == 0 {
		t.Fatal("no Code constants found; the walk is not reaching the sources")
	}
	return codes
}

// One public code, one constant message: every code has an entry, none of the
// messages is a format string, and an entry exists for no code that is not
// declared.
func TestEveryPublicCodeHasOneConstantMessage(t *testing.T) {
	codes := publicCodes(t)
	declared := map[string]bool{}
	for name, code := range codes {
		declared[code] = true
		msg, ok := publicMessages[code]
		if !ok || msg == "" {
			t.Errorf("%s (%q) has no public message", name, code)
		}
		if strings.Contains(msg, "%") {
			t.Errorf("%s: the message %q looks like a format string", name, msg)
		}
	}
	for code := range publicMessages {
		if !declared[code] {
			t.Errorf("publicMessages holds %q, which no Code constant declares", code)
		}
	}
}

// A public message names the operation and the recovery; words for the
// mechanism behind it would tell a client how the issuer is built.
func TestPublicMessagesNameNoMechanism(t *testing.T) {
	for code, msg := range publicMessages {
		for _, word := range []string{"serve process", "registry", "directory", "jti", "socket", "/"} {
			if strings.Contains(strings.ToLower(msg), word) {
				t.Errorf("%s: %q names the mechanism (%q)", code, msg, word)
			}
		}
	}
}

// The class guard: refuse takes (status, code constant, detail) and nothing
// else, and an IssueError is only ever built inside refuse, so no call site can
// put request or host data into a message.
func TestNoRefusalCarriesFormatArgumentsOrABypass(t *testing.T) {
	codes := publicCodes(t)
	known := map[string]bool{}
	for name := range codes {
		known[name] = true
	}
	calls := 0
	for _, f := range parsePackageSources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				// refuse is the one place an IssueError is built.
				return x.Name.Name != "refuse"
			case *ast.CallExpr:
				id, ok := x.Fun.(*ast.Ident)
				if !ok || id.Name != "refuse" {
					return true
				}
				calls++
				if len(x.Args) != 3 {
					t.Errorf("refuse called with %d arguments, want (status, code, detail)", len(x.Args))
					return true
				}
				code, ok := x.Args[1].(*ast.Ident)
				if !ok || !known[code.Name] {
					t.Errorf("refuse's code must be one of the Code constants, got %T", x.Args[1])
				}
			case *ast.CompositeLit:
				if id, ok := x.Type.(*ast.Ident); ok && id.Name == "IssueError" {
					t.Errorf("IssueError built outside refuse")
				}
			}
			return true
		})
	}
	if calls < 10 {
		t.Fatalf("only %d refuse calls found; the walk is not reaching the issuer", calls)
	}
}

// refuse returns the same message whatever the detail says.
func TestRefuseMessageIsIndependentOfDetail(t *testing.T) {
	for code, want := range publicMessages {
		a := refuse(http.StatusForbidden, code, errors.New("uid 1000 pid 7 /run/example/path"))
		b := refuse(http.StatusForbidden, code, nil)
		if a.Message != want || b.Message != want || a.Code != code {
			t.Errorf("%s: %q / %q, want %q", code, a.Message, b.Message, want)
		}
		if strings.Contains(a.Error(), "1000") || strings.Contains(a.Error(), "/run/") {
			t.Errorf("%s: Error() leaks the detail: %s", code, a.Error())
		}
	}
}

// Two requests that differ only in the variable data they carry get the same
// public message, and the variable data is in the cause.
func TestRefusalsForDifferentInputsShareOneMessage(t *testing.T) {
	f := newFixture(t, nil)
	parent, _ := mustSession(t, f, selfPeer(10), SessionRequest{})
	var msgs []string
	for _, pid := range []int32{11, 12} {
		_, err := f.issuer.IssueChild(selfPeer(pid), ChildRequest{ParentToken: parent.Token, AgentType: "example-builder", AgentID: "a1"})
		ie, ok := IsIssueError(err)
		if !ok {
			t.Fatalf("got %v", err)
		}
		msgs = append(msgs, ie.Message)
	}
	for _, name := range []string{"example-one", "example-two"} {
		_, err := f.issuer.IssueSession(selfPeer(10), SessionRequest{Definition: name})
		ie, _ := IsIssueError(err)
		msgs = append(msgs, ie.Message)
	}
	if msgs[0] != msgs[1] || msgs[2] != msgs[3] {
		t.Fatalf("messages vary with the input: %q", msgs)
	}
}
