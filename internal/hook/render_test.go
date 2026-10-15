package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const canonicalDefinition = `---
name: example-builder
description: Builds changes on a branch and opens a pull request.
tools: [Read, Edit, Bash]
model: sonnet
roles: [builder, reader]
trust_boundary: example
---
You build.

Keep the body as written.
`

func TestRenderClaudeCodeKeepsNativeMembersAndDropsIssuerOnes(t *testing.T) {
	out, err := RenderClaudeCode([]byte(canonicalDefinition))
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nname: example-builder\ndescription: Builds changes on a branch and opens a pull request.\ntools: Read, Edit, Bash\nmodel: sonnet\n---\nYou build.\n\nKeep the body as written.\n"
	if string(out) != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if strings.Contains(string(out), "roles") || strings.Contains(string(out), "trust_boundary") {
		t.Fatal("an issuer-only member reached the native agent")
	}
}

func TestRenderIsStableAndRefusesWhatItCannotRender(t *testing.T) {
	a, err := RenderClaudeCode([]byte(canonicalDefinition))
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderClaudeCode(a)
	if err != nil {
		t.Fatalf("a rendered agent does not render again: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("rendering a rendered agent changed it:\n%s\n%s", a, b)
	}
	for name, in := range map[string]string{
		"no description": "---\nname: x\n---\nbody\n",
		"no name":        "---\ndescription: d\n---\nbody\n",
		"bad name":       "---\nname: ../x\ndescription: d\n---\nbody\n",
		"no frontmatter": "just text\n",
		"not closed":     "---\nname: x\ndescription: d\n",
		"bad tools":      "---\nname: x\ndescription: d\ntools: {a: b}\n---\n",
		"empty tool":     "---\nname: x\ndescription: d\ntools: [\"\"]\n---\n",
	} {
		if _, err := RenderClaudeCode([]byte(in)); err == nil {
			t.Errorf("%s was rendered", name)
		}
	}
}

func TestRenderQuotesADescriptionThatNeedsIt(t *testing.T) {
	out, err := RenderClaudeCode([]byte("---\nname: x\ndescription: \"a: b # c\"\n---\n"))
	if err != nil {
		t.Fatal(err)
	}
	front, _, err := splitForTest(out)
	if err != nil || !strings.Contains(front, `description: 'a: b # c'`) && !strings.Contains(front, `description: "a: b # c"`) {
		t.Fatalf("%q %v", out, err)
	}
}

// A scalar that YAML would read back as another type must come back as the same
// string: the runtime re-reads the rendered file with a YAML parser.
func TestRenderScalarsRoundTripAsStrings(t *testing.T) {
	for _, value := range []string{"true", "false", "null", "yes", "no", "1.5", "0x1F", "2026-10-14", "~", "007", "1e3"} {
		in := "---\nname: x\ndescription: \"" + value + "\"\nmodel: \"" + value + "\"\n---\nbody\n"
		out, err := RenderClaudeCode([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		front, _, err := splitForTest(out)
		if err != nil {
			t.Fatal(err)
		}
		var back map[string]any
		if err := yaml.Unmarshal([]byte(front), &back); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		for _, key := range []string{"description", "model"} {
			if got, ok := back[key].(string); !ok || got != value {
				t.Errorf("%s %s came back as %#v", key, value, back[key])
			}
		}
	}
}

func splitForTest(out []byte) (string, string, error) {
	s := string(out)
	rest := strings.TrimPrefix(s, "---\n")
	front, body, _ := strings.Cut(rest, "---\n")
	return front, body, nil
}

func TestReadDefinitionReadsOnlyARegularFileByNameOrPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example-builder.md"), []byte(canonicalDefinition), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDefinition(dir, "example-builder"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDefinition("", filepath.Join(dir, "example-builder.md")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../example-builder", "a/b", "", ".."} {
		if _, err := ReadDefinition(dir, name); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "example-builder.md"), filepath.Join(dir, "link.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDefinition(dir, "link"); err == nil {
		t.Error("a symlink was read")
	}
	big := filepath.Join(dir, "big.md")
	if err := os.WriteFile(big, make([]byte, maxDefinitionBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDefinition(dir, "big"); err == nil {
		t.Error("an oversized definition was read")
	}
}
