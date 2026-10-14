package config

import (
	"reflect"
	"strings"
	"testing"
)

// yamlKey is the config key of a struct field.
func yamlKey(f reflect.StructField) string {
	key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return key
}

// A path-valued key left untagged would pass validation as a relative path, so
// this fails for any string field named like a path that is not tagged.
func TestEveryIdentityPathFieldIsTaggedAbsolute(t *testing.T) {
	typ := reflect.TypeOf(IdentityConfig{})
	tagged := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		key := yamlKey(f)
		pathNamed := strings.HasSuffix(key, "_path") || strings.HasSuffix(key, "_dir") || strings.HasSuffix(key, "_root")
		if pathNamed && f.Type.Kind() != reflect.String {
			t.Errorf("identity.%s is path-named but is a %s; validate only checks strings, so extend it before adding this field", key, f.Type.Kind())
			continue
		}
		if pathNamed && f.Tag.Get(absPathTag) != "true" {
			t.Errorf("identity.%s is path-valued but not tagged `%s:\"true\"`", key, absPathTag)
		}
		if f.Tag.Get(absPathTag) == "true" {
			tagged++
			if f.Type.Kind() != reflect.String {
				t.Errorf("identity.%s is tagged %s but is not a string", key, absPathTag)
			}
		}
	}
	if tagged == 0 {
		t.Fatal("no identity field is tagged; the walk is not reaching the struct")
	}
}

func TestLoad_IdentityRefusesRelativePathNamingTheKey(t *testing.T) {
	typ := reflect.TypeOf(IdentityConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Tag.Get(absPathTag) != "true" {
			continue
		}
		key := yamlKey(f)
		t.Run(key, func(t *testing.T) {
			p := writeTemp(t, "identity:\n  "+key+": relative/"+key+"\n")
			_, err := Load(p)
			if err == nil || !strings.Contains(err.Error(), "identity."+key) || !strings.Contains(err.Error(), "absolute") {
				t.Fatalf("relative %s: %v", key, err)
			}
		})
	}
}

func TestLoad_IdentityAcceptsAbsolutePaths(t *testing.T) {
	p := writeTemp(t, "identity:\n  key_path: /srv/k.pem\n  definitions_dir: /srv/defs\n  jwks_path: /srv/jwks.json\n  socket_path: /run/x/id.sock\n  spawn_root: /run/x/spawn\n")
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}
