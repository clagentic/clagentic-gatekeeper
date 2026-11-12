package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// yamlUnmarshalerType marks a type that decodes its own node. The walk cannot
// see inside one, so it leaves the value to that type's own validation.
var yamlUnmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// unknownKeys returns the full dotted path of every key the document carries
// that no field of Config declares, in document order and each once. It reads
// the node tree the decoder works from, so a key that arrives through an
// anchor or a merge key is checked and the merge key itself is never reported.
// Keys already reported as removed identity keys are left out.
func unknownKeys(data []byte) ([]string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	w := &keyWalk{seen: map[string]bool{}, aliased: map[*yaml.Node]bool{}}
	for _, k := range removedIdentityKeys {
		w.seen["identity."+k] = true
	}
	w.collectAliased(&root)
	w.walk(&root, reflect.TypeOf(Config{}), "")
	return w.found, nil
}

type keyWalk struct {
	found []string
	seen  map[string]bool
	// aliased is every node an alias in the document points at.
	aliased map[*yaml.Node]bool
}

func (w *keyWalk) collectAliased(n *yaml.Node) {
	if n.Kind == yaml.AliasNode {
		w.aliased[n.Alias] = true
		return
	}
	for _, c := range n.Content {
		w.collectAliased(c)
	}
}

func (w *keyWalk) report(path string) {
	if w.seen[path] {
		return
	}
	w.seen[path] = true
	w.found = append(w.found, path)
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// yamlFieldNames maps each yaml key a struct type declares to its field.
func yamlFieldNames(t reflect.Type) map[string]reflect.StructField {
	out := map[string]reflect.StructField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = f
	}
	return out
}

// pairs returns the key and value nodes of a mapping with every merge key
// expanded in place, which is the entry set the decoder sees.
func pairs(n *yaml.Node) [][2]*yaml.Node {
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag != "!!merge" {
			out = append(out, [2]*yaml.Node{k, v})
			continue
		}
		for _, src := range mergeSources(v) {
			out = append(out, pairs(src)...)
		}
	}
	return out
}

// mergeSources is the mappings a merge key's value names: one mapping or alias,
// or a sequence of them.
func mergeSources(v *yaml.Node) []*yaml.Node {
	if v.Kind == yaml.AliasNode {
		v = v.Alias
	}
	switch v.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{v}
	case yaml.SequenceNode:
		var out []*yaml.Node
		for _, item := range v.Content {
			if item.Kind == yaml.AliasNode {
				item = item.Alias
			}
			if item.Kind == yaml.MappingNode {
				out = append(out, item)
			}
		}
		return out
	}
	return nil
}

func (w *keyWalk) walk(n *yaml.Node, t reflect.Type, path string) {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) > 0 {
			w.walk(n.Content[0], t, path)
		}
		return
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if reflect.PtrTo(t).Implements(yamlUnmarshalerType) {
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return
		}
		fields := yamlFieldNames(t)
		for _, p := range pairs(n) {
			key := joinPath(path, p[0].Value)
			f, ok := fields[p[0].Value]
			if !ok {
				// A key whose value is an anchor the document uses elsewhere is
				// a place to define it, not a setting. What it holds is checked
				// where an alias or merge key brings it in.
				if !w.aliased[p[1]] {
					w.report(key)
				}
				continue
			}
			w.walk(p[1], f.Type, key)
		}
	case reflect.Map:
		// Entry names are free-form; only the entries' own keys are checked.
		if n.Kind != yaml.MappingNode {
			return
		}
		for _, p := range pairs(n) {
			w.walk(p[1], t.Elem(), joinPath(path, p[0].Value))
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range n.Content {
			w.walk(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

// UnknownKeys returns the full dotted path of every key the config carries that
// no setting declares, such as a misspelling. Load keeps loading when there are
// some; it never refuses for one.
func (c *Config) UnknownKeys() []string { return c.unknownKeys }

// UnknownKeyWarnings returns one line per unknown key, for stderr.
func (c *Config) UnknownKeyWarnings() []string {
	lines := make([]string, len(c.unknownKeys))
	for i, k := range c.unknownKeys {
		lines[i] = fmt.Sprintf("config: unknown key %s has no effect; check its spelling against config.example.yaml", k)
	}
	return lines
}
