package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"gopkg.in/yaml.v3"
)

const maxDefinitionBytes = 64 << 10

var (
	reName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	reRole = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// ErrUnknownDefinition is returned when no usable definition has the name.
var ErrUnknownDefinition = errors.New("unknown definition")

// Definition is one agent definition: the role ceiling its holders may have.
type Definition struct {
	Name          string
	Roles         []string
	TrustBoundary string
}

// Definitions reads <Dir>/<name>.md files. The directory is the only roster:
// nothing here or in the config names an agent.
type Definitions struct {
	Dir string
}

type frontmatter struct {
	Name          string   `yaml:"name"`
	Roles         []string `yaml:"roles"`
	TrustBoundary string   `yaml:"trust_boundary"`
}

// Load reads and validates the definition called name. A name that is not a
// plain identifier is refused before any path is built, so it cannot walk out
// of Dir.
func (d Definitions) Load(name string) (Definition, error) {
	if d.Dir == "" {
		return Definition{}, fmt.Errorf("%w: no identity.definitions_dir is configured", ErrUnknownDefinition)
	}
	if !reName.MatchString(name) {
		return Definition{}, fmt.Errorf("%w: %q is not a valid definition name", ErrUnknownDefinition, name)
	}
	fd, err := syscall.Open(filepath.Join(d.Dir, name+".md"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Definition{}, fmt.Errorf("%w: %q", ErrUnknownDefinition, name)
	}
	f := os.NewFile(uintptr(fd), name+".md")
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return Definition{}, fmt.Errorf("%w: %q is not a regular file", ErrUnknownDefinition, name)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxDefinitionBytes+1))
	if err != nil || len(raw) > maxDefinitionBytes {
		return Definition{}, fmt.Errorf("%w: %q is unreadable or too large", ErrUnknownDefinition, name)
	}
	fm, err := parseFrontmatter(raw)
	if err != nil {
		return Definition{}, fmt.Errorf("%w: %q: %v", ErrUnknownDefinition, name, err)
	}
	if fm.Name != name {
		return Definition{}, fmt.Errorf("%w: file %q declares name %q", ErrUnknownDefinition, name, fm.Name)
	}
	seen := map[string]bool{}
	roles := make([]string, 0, len(fm.Roles))
	for _, r := range fm.Roles {
		if !reRole.MatchString(r) {
			return Definition{}, fmt.Errorf("%w: %q has an invalid role %q", ErrUnknownDefinition, name, r)
		}
		if !seen[r] {
			seen[r] = true
			roles = append(roles, r)
		}
	}
	return Definition{Name: fm.Name, Roles: roles, TrustBoundary: fm.TrustBoundary}, nil
}

func parseFrontmatter(raw []byte) (frontmatter, error) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(raw, []byte("---\n")) {
		return frontmatter{}, errors.New("no YAML frontmatter")
	}
	rest := raw[len("---\n"):]
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return frontmatter{}, errors.New("frontmatter is not closed")
	}
	var fm frontmatter
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		return frontmatter{}, fmt.Errorf("frontmatter: %v", err)
	}
	return fm, nil
}
