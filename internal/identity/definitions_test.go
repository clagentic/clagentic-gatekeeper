//go:build linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefinitionParsing(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"example-ok.md":      "---\nname: example-ok\nroles: [builder, reviewer, builder]\ntrust_boundary: sandbox\nextra: ignored\n---\n# body\n",
		"example-crlf.md":    "---\r\nname: example-crlf\r\nroles: [reader]\r\n---\r\nbody\r\n",
		"example-nofm.md":    "just text\n",
		"example-open.md":    "---\nname: example-open\nroles: [reader]\n",
		"example-badrole.md": "---\nname: example-badrole\nroles: [Not_A_Role]\n---\n",
		"example-junk.md":    "---\nname: example-junk\nroles: [merger]\n---junk\nbody\n",
		"example-trail.md":   "---\nname: example-trail\nroles: [merger]\n--- \nbody\n",
		"example-long.md":    "---\nname: example-long\nroles: [merger]\n----\nbody\n",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := newDefs(t, dir)
	def, err := d.Load("example-ok")
	if err != nil || !reflect.DeepEqual(def.Roles, []string{"builder", "reviewer"}) || def.TrustBoundary != "sandbox" {
		t.Fatalf("%+v %v", def, err)
	}
	if def, err := d.Load("example-crlf"); err != nil || !reflect.DeepEqual(def.Roles, []string{"reader"}) {
		t.Fatalf("%+v %v", def, err)
	}
	for _, bad := range []string{"example-nofm", "example-open", "example-badrole", "example-missing", "example-junk", "example-trail", "example-long"} {
		if _, err := d.Load(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := newDefs(t, "").Load("example-ok"); err == nil {
		t.Error("unconfigured directory accepted a definition")
	}
}

func TestDefinitionSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.md")
	if err := os.WriteFile(target, []byte("---\nname: example-link\nroles: [merger]\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "example-link.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := newDefs(t, dir).Load("example-link"); err == nil {
		t.Fatal("symlinked definition accepted")
	}
}

// A definition grants roles, so whoever can write one chooses them. Start
// refuses a file writable by group or other, naming it, and Load refuses one
// that becomes so afterwards.
func TestDefinitionFileWritableByOthersRefusedAtStartAndAtLoad(t *testing.T) {
	dir := t.TempDir()
	writeDefinition(t, dir, "example-ok", "builder")
	writeDefinition(t, dir, "example-loose", "merger")
	if err := os.Chmod(filepath.Join(dir, "example-loose.md"), 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDefinitions(dir); err == nil || !strings.Contains(err.Error(), "example-loose.md") {
		t.Fatalf("start with a group-writable definition: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "example-loose.md"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := newDefs(t, dir)
	if _, err := d.Load("example-loose"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "example-loose.md"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Load("example-loose"); !errors.Is(err, ErrUnknownDefinition) {
		t.Fatalf("a definition made world-writable after start was loaded: %v", err)
	}
}

func TestDefinitionOwnedByAnotherUidRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file to another uid")
	}
	dir := t.TempDir()
	writeDefinition(t, dir, "example-foreign", "merger")
	if err := os.Chown(filepath.Join(dir, "example-foreign.md"), 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDefinitions(dir); err == nil || !strings.Contains(err.Error(), "example-foreign.md") {
		t.Fatalf("start with a foreign-owned definition: %v", err)
	}
}

// Every trust root is refused when another uid can write it or an ancestor: a
// writer of the directory could swap a definition, or the directory itself.
func TestDefinitionsDirectoryWritableByOthersRefusedNamingPath(t *testing.T) {
	outer := t.TempDir()
	for name, leaf := range map[string]string{"directory": "defs", "ancestor": "mid/defs"} {
		root := filepath.Join(outer, name)
		defs := filepath.Join(root, leaf)
		if err := os.MkdirAll(defs, 0o755); err != nil {
			t.Fatal(err)
		}
		loose := defs
		if name == "ancestor" {
			loose = filepath.Join(root, "mid")
		}
		if err := os.Chmod(loose, 0o775); err != nil {
			t.Fatal(err)
		}
		_, err := NewDefinitions(defs)
		if err == nil || !strings.Contains(err.Error(), loose) {
			t.Errorf("%s: got %v, want a refusal naming %s", name, err, loose)
		}
	}
}
