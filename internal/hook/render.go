package hook

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

const maxDefinitionBytes = 64 << 10

// ReadDefinition reads a definition file: path is a file, or, with dir set, a
// definition name resolved in dir. Only a regular file is read, so a FIFO or a
// device cannot stall the command.
func ReadDefinition(dir, arg string) ([]byte, error) {
	path := arg
	if dir != "" {
		if !safeName.MatchString(arg) {
			return nil, fmt.Errorf("definition name %q is not a plain name", arg)
		}
		path = filepath.Join(dir, arg+".md")
	}
	// One handle for the check and the read: a path swapped for a FIFO or a link
	// between a separate check and open cannot stall or redirect the command.
	f, _, err := identity.OpenRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxDefinitionBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDefinitionBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxDefinitionBytes)
	}
	return raw, nil
}

// canonical is the runtime-neutral frontmatter. roles and trust_boundary are the
// issuer's own members: they set the ceiling an assertion carries and have no
// meaning to a runtime, so a rendered agent never carries them.
type canonical struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Tools       yaml.Node `yaml:"tools"`
	Model       string    `yaml:"model"`
}

// RenderClaudeCode converts a canonical definition to the native agent format of
// Claude Code: frontmatter with name, description, tools (comma separated) and
// model, then the body unchanged. The native format requires a description, so
// a definition without one is refused rather than given an invented one.
func RenderClaudeCode(raw []byte) ([]byte, error) {
	front, body, err := identity.SplitFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	var c canonical
	if err := yaml.Unmarshal(front, &c); err != nil {
		return nil, fmt.Errorf("frontmatter: %w", err)
	}
	if !safeName.MatchString(c.Name) {
		return nil, errors.New("the definition has no usable name")
	}
	if strings.TrimSpace(c.Description) == "" {
		return nil, errors.New("the definition has no description, which the native format requires")
	}
	tools, err := toolList(c.Tools)
	if err != nil {
		return nil, err
	}

	m := &yaml.Node{Kind: yaml.MappingNode}
	add := func(k, v string) {
		// An explicit string tag makes the encoder quote a value the runtime would
		// otherwise read back as a bool, null or number ("true", "null", "1.5").
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	add("name", c.Name)
	add("description", c.Description)
	if tools != "" {
		add("tools", tools)
	}
	if c.Model != "" {
		add("model", c.Model)
	}
	head, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("---\n")
	out.Write(head)
	out.WriteString("---\n")
	out.Write(body)
	return out.Bytes(), nil
}

// toolList accepts tools as a YAML list or as one comma separated string.
func toolList(n yaml.Node) (string, error) {
	switch n.Kind {
	case 0:
		return "", nil
	case yaml.ScalarNode:
		return strings.TrimSpace(n.Value), nil
	case yaml.SequenceNode:
		var names []string
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode || strings.TrimSpace(item.Value) == "" {
				return "", errors.New("tools must be a list of names")
			}
			names = append(names, strings.TrimSpace(item.Value))
		}
		return strings.Join(names, ", "), nil
	}
	return "", errors.New("tools must be a list of names or one comma separated string")
}
