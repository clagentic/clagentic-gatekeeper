//go:build linux

package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// Algorithm names from the contract's section 2.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
)

type publicKey struct {
	jwk JWK
	ed  ed25519.PublicKey
	ec  *ecdsa.PublicKey
}

// Keyring holds the current signing key and every published public key.
type Keyring struct {
	current publicKey
	edPriv  ed25519.PrivateKey
	ecPriv  *ecdsa.PrivateKey
	public  []publicKey
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// LoadKeyring reads the signing key. wantAlg may be empty, in which case the
// key type decides; otherwise it must agree with the key.
func LoadKeyring(keyPath, wantAlg string) (*Keyring, error) {
	der, err := readPrivateKeyPEM(keyPath, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", keyPath, err)
	}
	kr := &Keyring{}
	switch k := parsed.(type) {
	case ed25519.PrivateKey:
		kr.edPriv = k
		kr.current = edPublic(k.Public().(ed25519.PublicKey))
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing key %s: only P-256 is supported for ES256", keyPath)
		}
		kr.ecPriv = k
		kr.current = ecPublic(&k.PublicKey)
	default:
		return nil, fmt.Errorf("signing key %s: unsupported key type %T", keyPath, parsed)
	}
	if wantAlg != "" && wantAlg != kr.current.jwk.Alg {
		return nil, fmt.Errorf("identity.alg %q does not match the %s key at %s", wantAlg, kr.current.jwk.Alg, keyPath)
	}
	kr.public = []publicKey{kr.current}
	return kr, nil
}

// maxKeyFileBytes bounds a key file read; a PKCS#8 key is a few hundred bytes.
const maxKeyFileBytes = 64 << 10

// readPrivateKeyPEM enforces the key-handling rule from the contract's
// security section (a regular file, mode 0600, owned by the serving uid) and
// returns the decoded PEM block. Its directory is verified like every trust
// root, the file is opened once relative to it without following links, and
// owner and mode are read from that descriptor, so the bytes parsed are those
// of the inode that was validated.
func readPrivateKeyPEM(path, wantType string) ([]byte, error) {
	dir, err := openTrustedDir(filepath.Dir(path), 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, fi, err := openRegularAt(dir, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has group or other permission bits (%#o); it must be 0600", path, fi.Mode().Perm())
	}
	if uid, ok := ownerUID(fi); !ok || int(uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s is not owned by the serving uid", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeyFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxKeyFileBytes)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != wantType {
		return nil, fmt.Errorf("%s: no %q PEM block", path, wantType)
	}
	return block.Bytes, nil
}

// thumbprint is the RFC 7638 SHA-256 JWK thumbprint, used as the kid so two
// keys can never share one.
func thumbprint(required map[string]string, order []string) string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range order {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%q:%q", k, required[k])
	}
	sb.WriteByte('}')
	sum := sha256.Sum256([]byte(sb.String()))
	return b64(sum[:])
}

func edPublic(pub ed25519.PublicKey) publicKey {
	x := b64(pub)
	kid := thumbprint(map[string]string{"crv": "Ed25519", "kty": "OKP", "x": x}, []string{"crv", "kty", "x"})
	return publicKey{ed: pub, jwk: JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, Alg: AlgEdDSA, Use: "sig", X: x}}
}

func ecPublic(pub *ecdsa.PublicKey) publicKey {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	xs, ys := b64(x), b64(y)
	kid := thumbprint(map[string]string{"crv": "P-256", "kty": "EC", "x": xs, "y": ys}, []string{"crv", "kty", "x", "y"})
	return publicKey{ec: pub, jwk: JWK{Kty: "EC", Crv: "P-256", Kid: kid, Alg: AlgES256, Use: "sig", X: xs, Y: ys}}
}

// JWKS returns the published key set: the current signing key only.
func (k *Keyring) JWKS() JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(k.public))}
	for _, p := range k.public {
		out.Keys = append(out.Keys, p.jwk)
	}
	return out
}

// Kid is the key id new assertions carry.
func (k *Keyring) Kid() string { return k.current.jwk.Kid }

// Alg is the algorithm new assertions are signed with.
func (k *Keyring) Alg() string { return k.current.jwk.Alg }

// Sign returns the raw signature over input in the JWS wire form: the Ed25519
// signature, or the 64-byte R||S form for ES256.
func (k *Keyring) Sign(input []byte) ([]byte, error) {
	if k.edPriv != nil {
		return ed25519.Sign(k.edPriv, input), nil
	}
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, k.ecPriv, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// Verify checks sig over input against the published key named by kid, and
// requires the key to be of the algorithm alg.
func (k *Keyring) Verify(kid, alg string, input, sig []byte) bool {
	for _, p := range k.public {
		if p.jwk.Kid != kid || p.jwk.Alg != alg {
			continue
		}
		if p.ed != nil {
			return ed25519.Verify(p.ed, input, sig)
		}
		if len(sig) != 64 {
			return false
		}
		digest := sha256.Sum256(input)
		return ecdsa.Verify(p.ec, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	return false
}

// MarshalJWKS renders the published document.
func (k *Keyring) MarshalJWKS() ([]byte, error) {
	return json.MarshalIndent(k.JWKS(), "", "  ")
}
