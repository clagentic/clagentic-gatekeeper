package livetest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The harness is part of a shipped product: nothing in it, its command, its
// make target or its documentation may name a host, a user, an agent or an
// absolute host path, or assume a crew, loadout or lore is present. The words
// are assembled from fragments so this file does not contain them either.
func TestHarnessNamesNoHostUserOrAgent(t *testing.T) {
	words := []string{
		"hol" + "den", "a" + "mos", "na" + "omi", "bob" + "bie", "peach" + "es", "ash" + "ford",
		"lo" + "re", "load" + "out", "cr" + "ew", "akue" + "hner",
	}
	word := regexp.MustCompile(`(?i)\b(` + strings.Join(words, "|") + `)\b`)
	dirs := []string{"ho" + "me", "ro" + "ot", "work" + "space", "Us" + "ers", "o" + "pt", "v" + "ar", "e" + "tc"}
	paths := regexp.MustCompile(`(^|[\s"'=(])/(` + strings.Join(dirs, "|") + `)\b`)

	files := []string{"../../Makefile", "../../docs/LIVE-TEST.md"}
	for _, dir := range []string{".", "../../cmd/livetest"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !e.IsDir() && e.Name() != "hygiene_test.go" {
				files = append(files, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if f == "../../Makefile" {
			// Only the live-test target belongs to the harness.
			_, text, _ = strings.Cut(text, "# Builds this tree and runs")
		}
		if m := word.FindString(text); m != "" {
			t.Errorf("%s names %q", f, m)
		}
		if m := paths.FindString(text); m != "" {
			t.Errorf("%s holds the absolute host path %q", f, strings.TrimSpace(m))
		}
	}
}
