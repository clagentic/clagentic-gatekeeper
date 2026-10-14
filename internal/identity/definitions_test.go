package identity

import (
	"os"
	"path/filepath"
	"reflect"
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
	d := Definitions{Dir: dir}
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
	if _, err := (Definitions{}).Load("example-ok"); err == nil {
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
	if _, err := (Definitions{Dir: dir}).Load("example-link"); err == nil {
		t.Fatal("symlinked definition accepted")
	}
}
