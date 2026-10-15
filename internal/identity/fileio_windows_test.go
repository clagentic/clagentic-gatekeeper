//go:build windows

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularFileRefusesOnWindowsWhateverThePath(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{regular, filepath.Join(t.TempDir(), "absent"), ""} {
		f, fi, err := OpenRegularFile(path)
		if f != nil || fi != nil || err != errOpenRegularUnsupported {
			t.Errorf("%q: file %v info %v err %v", path, f, fi, err)
		}
	}
}
