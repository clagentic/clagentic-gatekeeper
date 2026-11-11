package config

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// RetiredKeyConfig is one previous signing key, given as the public JWK members
// that identify it. Assertions it signed keep verifying until their exp because
// the key stays in the published key set; it never signs again.
type RetiredKeyConfig struct {
	Kty string
	Crv string
	X   string
	Y   string
	Kid string
	Alg string
	Use string

	// members are the member names the YAML entry carried, so a private or
	// unknown member is refused instead of dropped by the decoder.
	members []string
}

// retiredKeyMembers are the only members an entry may carry. "use" is accepted
// so an entry can be copied from a published key set unchanged.
var retiredKeyMembers = map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "kid": true, "alg": true, "use": true}

// UnmarshalYAML keeps every member name the entry carries.
func (r *RetiredKeyConfig) UnmarshalYAML(n *yaml.Node) error {
	var m map[string]string
	if err := n.Decode(&m); err != nil {
		return err
	}
	*r = RetiredKeyConfig{Kty: m["kty"], Crv: m["crv"], X: m["x"], Y: m["y"], Kid: m["kid"], Alg: m["alg"], Use: m["use"]}
	for name := range m {
		r.members = append(r.members, name)
	}
	sort.Strings(r.members)
	return nil
}

// validate checks the entries that can be judged without the signing key: no
// private member, no unknown member, the required members present and no
// repeated kid. That the kid is the key's RFC 7638 thumbprint, that the point
// is on the curve and that no entry is the current key are judged when the
// keyring is loaded, which is where the current key is known.
func validateRetiredKeys(keys []RetiredKeyConfig) error {
	seen := map[string]int{}
	for i, k := range keys {
		who := fmt.Sprintf("identity.retired_keys[%d]", i)
		if k.Kid != "" {
			who += fmt.Sprintf(" (kid %q)", k.Kid)
		}
		for _, name := range k.members {
			switch {
			case name == "d":
				return fmt.Errorf("%s has a private member d; retired_keys take public keys only, so remove the private key from the config", who)
			case !retiredKeyMembers[name]:
				return fmt.Errorf("%s has an unknown member %q; the members are kty, crv, x, y, kid, alg", who, name)
			}
		}
		for _, req := range []struct{ name, value string }{{"kty", k.Kty}, {"crv", k.Crv}, {"x", k.X}, {"kid", k.Kid}, {"alg", k.Alg}} {
			if req.value == "" {
				return fmt.Errorf("%s is missing member %s", who, req.name)
			}
		}
		if first, dup := seen[k.Kid]; dup {
			return fmt.Errorf("%s repeats the kid of identity.retired_keys[%d]", who, first)
		}
		seen[k.Kid] = i
	}
	return nil
}
