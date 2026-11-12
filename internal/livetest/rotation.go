package livetest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// mutateOneByte returns a copy of data with exactly one byte changed, so the
// copy differs from the original at a single offset and nowhere else.
func mutateOneByte(data []byte) []byte {
	out := append([]byte(nil), data...)
	if len(out) == 0 {
		return []byte{0}
	}
	i := len(out) / 2
	if out[i] == 'A' {
		out[i] = 'B'
	} else {
		out[i] = 'A'
	}
	return out
}

// retiredKeysYAML renders the identity.retired_keys block holding one inline
// public JWK, indented to sit under the identity: mapping.
func retiredKeysYAML(k identity.JWK) string {
	var sb strings.Builder
	sb.WriteString("  retired_keys:\n")
	fmt.Fprintf(&sb, "    - kty: %q\n      crv: %q\n      x: %q\n", k.Kty, k.Crv, k.X)
	if k.Y != "" {
		fmt.Fprintf(&sb, "      y: %q\n", k.Y)
	}
	fmt.Fprintf(&sb, "      kid: %q\n      alg: %q\n", k.Kid, k.Alg)
	return sb.String()
}

// withKid returns the token with its header's kid replaced. The signature is
// left as it was, so the result is a token naming a key the issuer never had.
func withKid(token, kid string) (string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", errors.New("not a three-segment compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("header is not base64url")
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	hdr["kid"] = kid
	out, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(out)
	return strings.Join(parts, "."), nil
}

// keyByKid finds one key of a published set.
func keyByKid(set identity.JWKS, kid string) (identity.JWK, bool) {
	for _, k := range set.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return identity.JWK{}, false
}
