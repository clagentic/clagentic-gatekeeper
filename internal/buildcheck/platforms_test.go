// Package buildcheck holds the check that the module compiles for every
// platform it supports. It has no non-test code.
package buildcheck

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// supportedPlatforms is every GOOS/GOARCH the module must compile for. A file
// that uses platform-specific syscalls carries a build constraint naming
// exactly the platforms that provide them; a constraint that is too wide (such
// as !windows, which admits plan9 and wasip1) breaks one of these builds.
// js/wasm is not supported: the gatekeeper is a host process manager and the
// developer-only cmd/livetest signals processes, which a browser cannot do.
var supportedPlatforms = []string{
	"linux/amd64", "linux/arm64",
	"darwin/amd64", "darwin/arm64",
	"freebsd/amd64", "openbsd/amd64", "netbsd/amd64", "dragonfly/amd64",
	"solaris/amd64", "illumos/amd64", "aix/ppc64",
	"windows/amd64", "windows/arm64",
	"plan9/amd64", "wasip1/wasm",
}

func TestModuleBuildsOnEverySupportedPlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles the module once per platform")
	}
	for _, p := range supportedPlatforms {
		goos, goarch, _ := strings.Cut(p, "/")
		t.Run(p, func(t *testing.T) {
			cmd := exec.Command("go", "build", "./...")
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build ./... for %s failed: %v\n%s", p, err, out)
			}
		})
	}
}
