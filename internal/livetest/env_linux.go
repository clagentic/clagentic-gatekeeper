//go:build linux

package livetest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// Invented definition names: the issuer's roster is whatever directory it is
// given, so the harness brings its own.
const (
	defLead    = "example-lead"
	defBuilder = "example-builder"
	// defOps carries the roles the other two do not, so every role a caller
	// mints has a definition whose assertion can be delivered for it.
	defOps = "example-ops"
)

// maxSocketPath is the sun_path limit of a unix socket.
const maxSocketPath = 108

// Env is one isolated deployment: a private directory holding the binary under
// test, an owner-only signing key, synthetic definitions and a running serve on
// a socket inside it. Close removes all of it.
type Env struct {
	Dir      string
	Bin      string
	Sock     string
	Spawn    string
	JWKSFile string

	opts  Options
	serve *exec.Cmd
	done  chan struct{}
	logs  bytes.Buffer

	// rt and rtErr cache the one-time runtime preparation shared by its shapes.
	rt    *runtimeSetup
	rtErr error

	// appKey is one App private key generated on first use and shared by every
	// mint fixture: generating an RSA key per shape would dominate the run.
	appKeyOnce sync.Once
	appKey     string
	appKeyErr  error
}

const minute = time.Minute

// callerEnv is this process's environment for a runtime that needs the caller's
// own state (credentials, say), minus the variables that would make the run
// something else: a delivery directory of an enclosing session, and the marker a
// runtime sets in its own children.
func callerEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CLAGENTIC_IDENTITY_DIR=") || strings.HasPrefix(kv, "CLAUDECODE=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// procResult is what a finished child process produced.
type procResult struct {
	Stdout, Stderr string
	Code           int
}

type runOpts struct {
	Stdin string
	// Env is appended to the minimal environment a child gets.
	Env []string
	// Full gives the child this process's whole environment instead.
	Full bool
	Dir  string
}

// NewEnv builds the binary (unless one is given), lays out the deployment and
// starts serve. On any error everything already created is removed.
func NewEnv(ctx context.Context, opts Options) (*Env, error) {
	opts = opts.withDefaults()
	// MkdirTemp creates the directory 0700: nothing below it is ever visible to
	// another user, including the key.
	dir, err := os.MkdirTemp(opts.TempParent, "gkl")
	if err != nil {
		return nil, fmt.Errorf("create the private directory: %w", err)
	}
	e := &Env{Dir: dir, opts: opts}
	if err := e.setup(ctx); err != nil {
		cerr := e.Close()
		return nil, errors.Join(err, cerr)
	}
	return e, nil
}

func (e *Env) setup(ctx context.Context) error {
	e.Sock = filepath.Join(e.Dir, "s.sock")
	if len(e.Sock) >= maxSocketPath {
		return fmt.Errorf("the socket path is %d bytes, over the %d-byte unix socket limit; give --temp-dir a shorter directory", len(e.Sock), maxSocketPath)
	}
	e.Spawn = filepath.Join(e.Dir, "spawn")
	e.JWKSFile = filepath.Join(e.Dir, "jwks.json")

	if err := e.prepareBinary(ctx); err != nil {
		return err
	}
	key, err := e.writeKey()
	if err != nil {
		return err
	}
	defs := filepath.Join(e.Dir, "defs")
	if err := os.Mkdir(defs, 0o700); err != nil {
		return err
	}
	for name, roles := range map[string]string{defLead: "[builder, reviewer]", defBuilder: "[builder]", defOps: "[merger, security, reader]"} {
		body := fmt.Sprintf("---\nname: %s\nroles: %s\n---\nSynthetic definition for the live harness.\n", name, roles)
		if err := writeOwnerOnly(filepath.Join(defs, name+".md"), []byte(body)); err != nil {
			return err
		}
	}
	cfg := fmt.Sprintf("identity:\n  key_path: %q\n  jwks_path: %q\n  definitions_dir: %q\n  spawn_root: %q\n  runtime_roles: [builder, reviewer]\n",
		key, e.JWKSFile, defs, e.Spawn)
	cfgPath := filepath.Join(e.Dir, "config.yaml")
	if err := writeOwnerOnly(cfgPath, []byte(cfg)); err != nil {
		return err
	}
	return e.startServe(ctx, cfgPath)
}

// prepareBinary builds the module under test, or adopts the binary it was given.
func (e *Env) prepareBinary(ctx context.Context) error {
	if e.opts.Binary != "" {
		if fi, err := os.Stat(e.opts.Binary); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("--binary does not name a regular file")
		}
		abs, err := filepath.Abs(e.opts.Binary)
		if err != nil {
			return err
		}
		e.Bin = abs
		return nil
	}
	binDir := filepath.Join(e.Dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		return err
	}
	e.Bin = filepath.Join(binDir, "gatekeeper")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", e.Bin, "./cmd/gatekeeper")
	cmd.Dir = e.opts.Source
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build the tree: %w\n%.2000s", err, out)
	}
	return nil
}

// writeKey creates the signing key owner-only from the first byte: the file is
// created with mode 0600 and never exists with a wider one.
func (e *Env) writeKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	path := filepath.Join(e.Dir, "key.pem")
	return path, writeOwnerOnly(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func writeOwnerOnly(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// startServe runs the real serve in its own process group, so teardown can
// remove it and anything it started, and waits until it answers.
func (e *Env) startServe(ctx context.Context, cfgPath string) error {
	cmd := exec.Command(e.Bin, "serve", "--config", cfgPath, "--socket", e.Sock)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = &e.logs
	cmd.Env = e.baseEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start serve: %w", err)
	}
	e.serve = cmd
	e.done = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(e.done)
	}()
	deadline := time.After(20 * time.Second)
	for {
		_, sockErr := os.Stat(e.Sock)
		_, keysErr := os.Stat(e.JWKSFile)
		if sockErr == nil && keysErr == nil {
			return nil
		}
		select {
		case <-e.done:
			return fmt.Errorf("serve exited before it was ready: %.1000s", e.logs.String())
		case <-deadline:
			return fmt.Errorf("serve was not ready in 20s: %.1000s", e.logs.String())
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// baseEnv is the minimal environment of a child: nothing of the caller's reaches
// it except the search path, and home and temporary directories are the private
// one.
func (e *Env) baseEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.Dir, "TMPDIR=" + e.Dir}
}

// run starts a child in its own process group, so cancellation reaches whatever
// it started, and returns its output. A child that exits non-zero is a result,
// not an error.
func (e *Env) run(ctx context.Context, o runOpts, name string, args ...string) (procResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = o.Dir
	if o.Full {
		cmd.Env = append(callerEnv(), o.Env...)
	} else {
		cmd.Env = append(e.baseEnv(), o.Env...)
	}
	if o.Stdin != "" {
		cmd.Stdin = bytes.NewReader([]byte(o.Stdin))
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := procResult{Stdout: out.String(), Stderr: errb.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ctx.Err() == nil:
		res.Code = ee.ExitCode()
	case ctx.Err() != nil:
		return res, ctx.Err()
	default:
		return res, err
	}
	return res, nil
}

// gk runs the binary under test with a bounded lifetime.
func (e *Env) gk(ctx context.Context, o runOpts, args ...string) (procResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return e.run(ctx, o, e.Bin, args...)
}

func (e *Env) client() identity.Client {
	return identity.Client{Socket: e.Sock, Timeout: 15 * time.Second}
}

// publishedKeys reads the key set the issuer wrote at start.
func (e *Env) publishedKeys() (identity.JWKS, error) {
	raw, err := os.ReadFile(e.JWKSFile)
	if err != nil {
		return identity.JWKS{}, err
	}
	var set identity.JWKS
	return set, json.Unmarshal(raw, &set)
}

// verify checks a token against the published key file and returns its claims.
func (e *Env) verify(token string) (Claims, error) {
	set, err := e.publishedKeys()
	if err != nil {
		return Claims{}, fmt.Errorf("read the published key set: %w", err)
	}
	return VerifyAssertion(token, set, time.Now())
}

// Close stops serve and everything started in its group, then removes the
// private directory, and reports anything it could not remove. It is safe to
// call more than once and after a partial setup.
func (e *Env) Close() error {
	var errs []error
	if e.serve != nil && e.serve.Process != nil {
		_ = syscall.Kill(-e.serve.Process.Pid, syscall.SIGTERM)
		select {
		case <-e.done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-e.serve.Process.Pid, syscall.SIGKILL)
			select {
			case <-e.done:
			case <-time.After(5 * time.Second):
				errs = append(errs, errors.New("serve did not exit"))
			}
		}
		e.serve = nil
	}
	if e.Dir != "" {
		if err := os.RemoveAll(e.Dir); err != nil {
			errs = append(errs, err)
		} else if _, err := os.Lstat(e.Dir); err == nil {
			errs = append(errs, errors.New("the private directory is still present"))
		}
	}
	return errors.Join(errs...)
}
