package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A documented step that creates key material must create it private from the
// first instant: every genpkey line is under umask 077, and no doc relies on a
// later chmod to restrict a file already written.
func TestDocumentedKeyCreationIsPrivateFromTheStart(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no docs found: %v", err)
	}
	files = append(files, filepath.Join("..", "..", "config.example.yaml"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "genpkey") && !strings.Contains(line, "umask 077") {
				t.Errorf("%s:%d creates a key without umask 077", f, i+1)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "chmod 0600") {
				t.Errorf("%s:%d restricts a key after it was written", f, i+1)
			}
		}
	}
}
