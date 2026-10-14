//go:build linux

package identity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

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
// TrustBoundary is parsed and carried but not yet enforced: no decision reads
// it, and a per-definition allow-list built on it is future work.
type Definition struct {
	Name          string
	Roles         []string
	TrustBoundary string
}

// Definitions reads <dir>/<name>.md files through a handle on the directory
// opened (and verified) once. The directory is the only roster: nothing here
// or in the config names an agent.
type Definitions struct {
	dir *os.File
}

type frontmatter struct {
	Name          string   `yaml:"name"`
	Roles         []string `yaml:"roles"`
	TrustBoundary string   `yaml:"trust_boundary"`
}

const definitionSuffix = ".md"

// NewDefinitions opens dir as a trust root: the directory and every ancestor
// must be owned by root or the serving uid and not writable by group or other,
// and so must each definition file already in it, because whoever can edit a
// definition chooses the roles it grants. An empty dir yields a reader that
// refuses every name.
func NewDefinitions(dir string) (*Definitions, error) {
	if dir == "" {
		return &Definitions{}, nil
	}
	h, err := openTrustedDir(dir, 0)
	if err != nil {
		return nil, fmt.Errorf("identity.definitions_dir: %w", err)
	}
	d := &Definitions{dir: h}
	if err := d.verifyFiles(); err != nil {
		h.Close()
		return nil, fmt.Errorf("identity.definitions_dir: %w", err)
	}
	return d, nil
}

// Close releases the directory handle.
func (d *Definitions) Close() error {
	if d == nil || d.dir == nil {
		return nil
	}
	return d.dir.Close()
}

// verifyFiles applies the owner and mode rule to every regular definition
// file. An entry that is not a regular file (a link, a FIFO, a directory) is
// the one documented skip: it is left alone here and refused when named. Any
// other open or stat failure refuses the start, naming the file.
func (d *Definitions) verifyFiles() error {
	scan, err := reopen(d.dir)
	if err != nil {
		return err
	}
	defer scan.Close()
	names, err := scan.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		if !strings.HasSuffix(n, definitionSuffix) {
			continue
		}
		f, fi, err := openRegularAt(d.dir, n)
		if err != nil {
			if isNotRegularEntry(err) {
				continue
			}
			// An unreadable regular definition cannot be checked, so serving
			// with it present would be serving with an unverified roster.
			return fmt.Errorf("cannot verify definition %s: %w", n, err)
		}
		f.Close()
		if err := checkTrustedFile(n, fi); err != nil {
			return err
		}
	}
	return nil
}

// Load reads and validates the definition called name. A name that is not a
// plain identifier is refused before it is used, so it cannot walk out of the
// directory.
func (d *Definitions) Load(name string) (Definition, error) {
	if d == nil || d.dir == nil {
		return Definition{}, fmt.Errorf("%w: no identity.definitions_dir is configured", ErrUnknownDefinition)
	}
	if !reName.MatchString(name) {
		return Definition{}, fmt.Errorf("%w: %q is not a valid definition name", ErrUnknownDefinition, name)
	}
	// A definition request must never block on, or follow a link to, something
	// that is not a plain file in the directory.
	f, fi, err := openRegularAt(d.dir, name+definitionSuffix)
	if err != nil {
		return Definition{}, fmt.Errorf("%w: %q: %v", ErrUnknownDefinition, name, err)
	}
	defer f.Close()
	if err := checkTrustedFile(name+definitionSuffix, fi); err != nil {
		return Definition{}, fmt.Errorf("%w: %q: %v", ErrUnknownDefinition, name, err)
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
	front, _, err := SplitFrontmatter(raw)
	if err != nil {
		return frontmatter{}, err
	}
	var fm frontmatter
	if err := yaml.Unmarshal(front, &fm); err != nil {
		return frontmatter{}, fmt.Errorf("frontmatter: %v", err)
	}
	return fm, nil
}
