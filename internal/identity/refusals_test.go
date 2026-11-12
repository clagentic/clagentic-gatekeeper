//go:build linux

package identity

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parsePackageSources(t *testing.T) []*ast.File { return parseSources(t, nil) }

// parseSources parses the package's non-test sources except those named in skip.
func parseSources(t *testing.T, skip map[string]bool) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || skip[n] {
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
	// Client.issue reads a refusal back off the wire into an IssueError: it
	// builds what the server already built, so it is the one site outside the
	// guard (see isWireReadBack). The rest of client.go is walked.
	violations, calls := refusalViolations(parsePackageSources(t), known)
	for _, v := range violations {
		t.Error(v)
	}
	if calls < 10 {
		t.Fatalf("only %d refuse calls found; the walk is not reaching the issuer", calls)
	}
}

// isWireReadBack reports whether fd is Client.issue, the one function that
// decodes a refusal from the wire into an IssueError.
func isWireReadBack(fd *ast.FuncDecl) bool {
	if fd.Name.Name != "issue" || fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	id, ok := fd.Recv.List[0].Type.(*ast.Ident)
	return ok && id.Name == "Client"
}

// issueErrorTyped reports whether e names the IssueError type or a pointer to it.
func issueErrorTyped(e ast.Expr) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "IssueError"
}

// issueErrorVars returns the names within fd that hold an IssueError: receivers,
// parameters, results and var declarations typed IssueError or *IssueError, and
// the first result of IsIssueError.
func issueErrorVars(fd *ast.FuncDecl) map[string]bool {
	vars := map[string]bool{}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			if issueErrorTyped(field.Type) {
				for _, n := range field.Names {
					vars[n.Name] = true
				}
			}
		}
	}
	addFields(fd.Recv)
	ast.Inspect(fd, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncType:
			addFields(x.Params)
			addFields(x.Results)
		case *ast.ValueSpec:
			if x.Type != nil && issueErrorTyped(x.Type) {
				for _, n := range x.Names {
					vars[n.Name] = true
				}
			}
		case *ast.AssignStmt:
			if len(x.Rhs) != 1 {
				break
			}
			if call, ok := x.Rhs[0].(*ast.CallExpr); ok {
				if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "IsIssueError" {
					if id, ok := x.Lhs[0].(*ast.Ident); ok {
						vars[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return vars
}

// refusalViolations walks files for every way an IssueError, or its message,
// can come into being other than through refuse: a composite literal, new, a
// zero-value declaration, and an assignment to the Message member of an
// IssueError. It also checks each refuse call's shape. calls is how many refuse
// calls it saw.
func refusalViolations(files []*ast.File, known map[string]bool) (violations []string, calls int) {
	isIssueError := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "IssueError"
	}
	for _, f := range files {
		var issueVars map[string]bool
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				// refuse is the one place an IssueError is built, and Client.issue
				// the one place one is decoded off the wire.
				if x.Name.Name == "refuse" || isWireReadBack(x) {
					return false
				}
				issueVars = issueErrorVars(x)
				return true
			case *ast.CallExpr:
				if fn, ok := x.Fun.(*ast.Ident); ok && fn.Name == "new" && len(x.Args) == 1 && isIssueError(x.Args[0]) {
					violations = append(violations, "IssueError built with new outside refuse")
					return true
				}
				id, ok := x.Fun.(*ast.Ident)
				if !ok || id.Name != "refuse" {
					return true
				}
				calls++
				if len(x.Args) != 3 {
					violations = append(violations, fmt.Sprintf("refuse called with %d arguments, want (status, code, detail)", len(x.Args)))
					return true
				}
				code, ok := x.Args[1].(*ast.Ident)
				if !ok || !known[code.Name] {
					violations = append(violations, fmt.Sprintf("refuse's code must be one of the Code constants, got %T", x.Args[1]))
				}
			case *ast.CompositeLit:
				if isIssueError(x.Type) {
					violations = append(violations, "IssueError built outside refuse")
				}
			case *ast.ValueSpec:
				if isIssueError(x.Type) {
					violations = append(violations, "IssueError declared as a zero value outside refuse")
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Message" {
						continue
					}
					// A Message member of some other type is not a public message.
					if recv, ok := sel.X.(*ast.Ident); ok && issueVars[recv.Name] {
						violations = append(violations, "a Message member assigned outside refuse")
					}
				}
			}
			return true
		})
	}
	return violations, calls
}

// The guard has to fail when the thing it guards happens. Each snippet builds an
// IssueError, or sets its message, by a route the guard must refuse.
func TestRefusalGuardCatchesEveryBypass(t *testing.T) {
	for name, body := range map[string]string{
		"composite literal":    `func f() *IssueError { return &IssueError{Code: "x"} }`,
		"new":                  `func f() *IssueError { return new(IssueError) }`,
		"zero-value var":       `func f() { var e IssueError; _ = e }`,
		"message assignment":   `func f(e *IssueError) { e.Message = "x" }`,
		"message reassignment": `func f(e IssueError) { e.Message, e.Code = "x", "y" }`,
		"message via decoded":  `func f(err error) { ie, _ := IsIssueError(err); ie.Message = "x" }`,
		"bypass in client.go":  `func (c Client) other() { var ie IssueError; _ = ie }`,
		"wrong receiver issue": `func (c Server) issue() { var ie IssueError; _ = ie }`,
		"refuse with 2 args":   `func f() { refuse(500, CodeInternal) }`,
		"refuse unknown code":  `func f() { refuse(500, "internal", nil) }`,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "snippet.go", "package identity\n"+body, 0)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := refusalViolations([]*ast.File{f}, map[string]bool{"CodeInternal": true}); len(v) == 0 {
				t.Fatalf("the guard passed %s", body)
			}
		})
	}
	for name, c := range map[string]struct {
		body  string
		calls int
	}{
		"refuse call":    {`func f() { refuse(500, CodeInternal, nil) }`, 1},
		"wire read-back": {`func (c Client) issue() { var ie IssueError; _ = ie }`, 0},
		"other message":  {`func f(o other) { o.Message = "x" }`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "snippet.go", "package identity\n"+c.body, 0)
		if err != nil {
			t.Fatal(err)
		}
		if v, calls := refusalViolations([]*ast.File{f}, map[string]bool{"CodeInternal": true}); len(v) != 0 || calls != c.calls {
			t.Fatalf("the guard refused %s: %v (%d calls)", name, v, calls)
		}
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
