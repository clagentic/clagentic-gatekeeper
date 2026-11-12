//go:build linux

package livetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// selfCheckShapes run the binary's own self-check against the isolated serve and
// verify a token across a key rotation. They need no runtime CLI.
func (e *Env) selfCheckShapes() []shape {
	return []shape{
		{"self-check/fresh-against-isolated-serve", e.shapeSelfCheckFresh},
		{"self-check/stale-after-one-byte-of-jwks-changes", e.shapeSelfCheckStale},
		{"issuer/rotation-old-kid-verifies-unknown-kid-refused", e.shapeRotation},
	}
}

func (e *Env) selfCheck(ctx context.Context, jwksPath string) (procResult, error) {
	return e.gk(ctx, runOpts{}, "self-check", "--socket", e.Sock, "--jwks-path", jwksPath)
}

func (e *Env) shapeSelfCheckFresh(ctx context.Context) error {
	res, err := e.selfCheck(ctx, e.JWKSFile)
	if err != nil {
		return err
	}
	if res.Code != 0 || !strings.Contains(res.Stdout, "jwks: fresh") {
		return fmt.Errorf("exit %d, want 0 and a fresh key set: %.300s %.300s", res.Code, res.Stdout, res.Stderr)
	}
	return nil
}

// shapeSelfCheckStale changes one byte of a copy of the published file: the
// original stays what the other shapes verify against.
func (e *Env) shapeSelfCheckStale(ctx context.Context) error {
	raw, err := os.ReadFile(e.JWKSFile)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(e.Dir, "stale-")
	if err != nil {
		return err
	}
	changed := filepath.Join(dir, "jwks.json")
	if err := writeOwnerOnly(changed, mutateOneByte(raw)); err != nil {
		return err
	}
	res, err := e.selfCheck(ctx, changed)
	if err != nil {
		return err
	}
	if res.Code == 0 {
		return fmt.Errorf("exit 0 for a key set file with one byte changed: %.300s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "jwks: stale") {
		return fmt.Errorf("non-zero exit %d, but the output does not report stale: %.300s %.300s", res.Code, res.Stdout, res.Stderr)
	}
	return nil
}

// rotationServe is one serve of the rotation shape, on its own socket and key
// set file so the run's shared issuer is never restarted.
type rotationServe struct {
	cmd  *exec.Cmd
	done chan struct{}
	logs bytes.Buffer
	sock string
	jwks string
}

func (r *rotationServe) stop() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	}
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			return errors.New("the rotation serve did not exit")
		}
	}
	r.cmd = nil
	return nil
}

// startRotationServe writes a config with the given extra identity lines and
// starts serve on it, waiting until the socket and key set file exist.
func (e *Env) startRotationServe(ctx context.Context, dir, name, extra string) (*rotationServe, *identity.JWKS, error) {
	priv, err := newSigningKeyPEM()
	if err != nil {
		return nil, nil, err
	}
	keyPath := filepath.Join(dir, name+"-key.pem")
	if err := writeOwnerOnly(keyPath, priv); err != nil {
		return nil, nil, err
	}
	r := &rotationServe{sock: filepath.Join(dir, "r.sock"), jwks: filepath.Join(dir, name+"-jwks.json")}
	if len(r.sock) >= maxSocketPath {
		return nil, nil, fmt.Errorf("the socket path is %d bytes, over the %d-byte unix socket limit", len(r.sock), maxSocketPath)
	}
	// A stopped serve may leave its socket path behind.
	if err := os.Remove(r.sock); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	cfg := fmt.Sprintf("identity:\n  key_path: %q\n  jwks_path: %q\n  definitions_dir: %q\n  spawn_root: %q\n  runtime_roles: [builder, reviewer]\n%s",
		keyPath, r.jwks, filepath.Join(e.Dir, "defs"), filepath.Join(dir, name+"-spawn"), extra)
	cfgPath := filepath.Join(dir, name+".yaml")
	if err := writeOwnerOnly(cfgPath, []byte(cfg)); err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(e.Bin, "serve", "--config", cfgPath, "--socket", r.sock)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = &r.logs
	cmd.Env = e.baseEnv()
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start the rotation serve: %w", err)
	}
	r.cmd = cmd
	r.done = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(r.done)
	}()
	deadline := time.After(20 * time.Second)
	for {
		_, sockErr := os.Stat(r.sock)
		_, keysErr := os.Stat(r.jwks)
		if sockErr == nil && keysErr == nil {
			break
		}
		select {
		case <-r.done:
			return nil, nil, fmt.Errorf("the rotation serve exited before it was ready: %.1000s", r.logs.String())
		case <-deadline:
			_ = r.stop()
			return nil, nil, fmt.Errorf("the rotation serve was not ready in 20s: %.1000s", r.logs.String())
		case <-ctx.Done():
			_ = r.stop()
			return nil, nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	set, err := readKeySet(r.jwks)
	if err != nil {
		_ = r.stop()
		return nil, nil, err
	}
	return r, &set, nil
}

// shapeRotation issues a token under one key, restarts serve with a new current
// key and the first one retired inline, and checks what a relying party reading
// the published key set then does with the old token and with an unknown kid.
func (e *Env) shapeRotation(ctx context.Context) error {
	dir, err := os.MkdirTemp(e.Dir, "rot-")
	if err != nil {
		return err
	}
	first, firstSet, err := e.startRotationServe(ctx, dir, "first", "")
	if err != nil {
		return err
	}
	defer func() { _ = first.stop() }()
	if len(firstSet.Keys) != 1 {
		return fmt.Errorf("the first serve publishes %d keys, want 1", len(firstSet.Keys))
	}
	oldKey := firstSet.Keys[0]
	issued, err := identity.Client{Socket: first.sock, Timeout: 15 * time.Second}.IssueSession(identity.SessionRequest{Definition: defBuilder})
	if err != nil {
		return fmt.Errorf("issue under the first key: %w", err)
	}
	if err := first.stop(); err != nil {
		return err
	}

	second, secondSet, err := e.startRotationServe(ctx, dir, "second", retiredKeysYAML(oldKey))
	if err != nil {
		return err
	}
	defer func() { _ = second.stop() }()
	if len(secondSet.Keys) != 2 {
		return fmt.Errorf("after the rotation the key set holds %d keys, want the new current key and the retired one", len(secondSet.Keys))
	}
	if _, ok := keyByKid(*secondSet, oldKey.Kid); !ok {
		return fmt.Errorf("the retired kid %q is not in the key set published after the rotation", oldKey.Kid)
	}

	served, err := identity.Client{Socket: second.sock, Timeout: 15 * time.Second}.FetchJWKS()
	if err != nil {
		return fmt.Errorf("the rotated serve does not serve the key set: %w", err)
	}
	for name, set := range map[string]identity.JWKS{"file": *secondSet, "socket": served} {
		c, err := VerifyAssertion(issued.Token, set, time.Now())
		if err != nil {
			return fmt.Errorf("the token issued under the previous key does not verify against the %s key set: %w", name, err)
		}
		if c.Exp <= time.Now().Unix() {
			return errors.New("the old token verified at or after its exp")
		}
	}

	fresh, err := identity.Client{Socket: second.sock, Timeout: 15 * time.Second}.IssueSession(identity.SessionRequest{Definition: defBuilder})
	if err != nil {
		return fmt.Errorf("issue under the new key: %w", err)
	}
	if _, err := VerifyAssertion(fresh.Token, *secondSet, time.Now()); err != nil {
		return fmt.Errorf("a token under the new current key does not verify: %w", err)
	}

	unknown, err := withKid(issued.Token, "unknown-"+oldKey.Kid)
	if err != nil {
		return err
	}
	if _, err := VerifyAssertion(unknown, *secondSet, time.Now()); err == nil {
		return errors.New("a token under an unknown kid verified")
	} else if !strings.Contains(err.Error(), "not in the published key set") {
		return fmt.Errorf("an unknown kid was refused, but not as an unknown kid: %w", err)
	}
	return nil
}
