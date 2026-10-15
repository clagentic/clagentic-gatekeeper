//go:build linux

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file holds the mint shapes: the real binary's mint command, run as a
// separate process, resolving identity from an assertion this run's issuer
// really issued and delivered. Only the git host's token endpoint is stubbed,
// by a server inside the harness; the broker is the environment broker.

const mintToken = "ghs_livetest_token"

// mintFixture is the stub token endpoint plus the environment the mint process
// reads its App credentials from.
type mintFixture struct {
	cfgPath string
	env     []string
	close   func()
}

// newMintFixture writes a mint config trusting this run's issuer when
// withAssertion is set, and otherwise one that resolves the identity named by
// a configured environment variable.
func (e *Env) newMintFixture(withAssertion bool) (*mintFixture, error) {
	stub := newTokenStub(nil)
	srv := stub.srv
	keyPEM, err := e.appKeyPEM()
	if err != nil {
		srv.Close()
		return nil, err
	}

	env := []string{"LIVETEST_APP_ID=12345", "LIVETEST_INSTALL_ID=67890", "LIVETEST_APP_KEY=" + keyPEM, "LIVETEST_APP_SLUG=example-app"}
	role := func(name, extra string) string {
		return fmt.Sprintf("  %s:\n    app_id_path: LIVETEST_APP_ID\n    installation_id_path: LIVETEST_INSTALL_ID\n    private_key_path: LIVETEST_APP_KEY\n    app_slug: example-app\n    app_slug_path: LIVETEST_APP_SLUG\n%s", name, extra)
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "github:\n  owner: example\n  api_base: %s\nbroker:\n  type: env\nroles:\n", srv.URL)
	if withAssertion {
		cfg.WriteString(role("builder", "") + role("merger", ""))
		fmt.Fprintf(&cfg, "attestation:\n  allow_os_user: false\n  assertion:\n    issuers:\n      - iss: unix://%s\n        jwks: %s\n", e.Sock, e.JWKSFile)
	} else {
		cfg.WriteString(role("builder", "    entitled_identities:\n      - example-configured-caller\n"))
		cfg.WriteString("attestation:\n  allow_os_user: false\n  configured:\n    type: env\n    source: LIVETEST_CALLER\n")
		env = append(env, "LIVETEST_CALLER=example-configured-caller")
	}
	path := filepath.Join(e.Dir, fmt.Sprintf("mint-%d.yaml", len(e.mintConfigs())))
	if err := writeOwnerOnly(path, []byte(cfg.String())); err != nil {
		srv.Close()
		return nil, err
	}
	return &mintFixture{cfgPath: path, env: env, close: srv.Close}, nil
}

func (e *Env) mintConfigs() []string {
	m, _ := filepath.Glob(filepath.Join(e.Dir, "mint-*.yaml"))
	return m
}

// assertionAssignment asks the process adapter for a delivery of the builder
// definition, exactly as a launcher would, and returns the KEY=VALUE it prints.
func (e *Env) assertionAssignment(ctx context.Context) (string, error) {
	return e.assertionAssignmentFor(ctx, defBuilder)
}

// assertionAssignmentFor is assertionAssignment for another definition.
func (e *Env) assertionAssignmentFor(ctx context.Context, definition string) (string, error) {
	res, err := e.gk(ctx, runOpts{}, "hook", "process", "--socket", e.Sock, "--definition", definition)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("hook process exit %d: %.300s", res.Code, res.Stderr)
	}
	assignment := strings.TrimSpace(res.Stdout)
	if !strings.HasPrefix(assignment, identityDirEnv+"=") {
		return "", fmt.Errorf("unexpected assignment %q", assignment)
	}
	return assignment, nil
}

const identityDirEnv = "CLAGENTIC_IDENTITY_DIR"

// runMint runs `mint` as the caller would, directly or under a command wrapper.
func (e *Env) runMint(ctx context.Context, f *mintFixture, extraEnv []string, viaWrapper bool, role string) (procResult, error) {
	args := []string{"mint", "--role", role, "--config", f.cfgPath, "--json"}
	env := append(append([]string{}, f.env...), extraEnv...)
	if !viaWrapper {
		return e.gk(ctx, runOpts{Env: env}, args...)
	}
	sh, err := lookShell()
	if err != nil {
		return procResult{}, err
	}
	return e.gk2Env(ctx, env, sh, append([]string{"-c", wrapperScript, e.Bin}, args...)...)
}

func (e *Env) gk2Env(ctx context.Context, env []string, name string, args ...string) (procResult, error) {
	ctx, cancel := context.WithTimeout(ctx, minute)
	defer cancel()
	return e.run(ctx, runOpts{Env: env}, name, args...)
}

type mintOutput struct {
	Token    string `json:"token"`
	AppSlug  string `json:"app_slug"`
	Identity *struct {
		Subject string `json:"subject"`
		Source  string `json:"source"`
		Grade   string `json:"grade"`
	} `json:"identity"`
}

func (e *Env) mintShapes() []shape {
	return []shape{
		{"mint/assertion-delivered-direct", e.shapeMintAssertion(false)},
		{"mint/assertion-delivered-under-command-wrapper", e.shapeMintAssertion(true)},
		{"mint/role-outside-assertion-refused", e.shapeMintOtherRole},
		{"mint/no-assertion-configured-provider-unchanged", e.shapeMintConfigured},
		{"mint/tampered-assertion-refused", e.shapeMintForged},
	}
}

func (e *Env) shapeMintAssertion(viaWrapper bool) func(context.Context) error {
	return func(ctx context.Context) error {
		f, err := e.newMintFixture(true)
		if err != nil {
			return err
		}
		defer f.close()
		assignment, err := e.assertionAssignment(ctx)
		if err != nil {
			return err
		}
		res, err := e.runMint(ctx, f, []string{assignment}, viaWrapper, "builder")
		if err != nil {
			return err
		}
		if res.Code != 0 {
			return fmt.Errorf("mint exit %d: %.300s", res.Code, res.Stderr)
		}
		var out mintOutput
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			return fmt.Errorf("mint did not print JSON: %w", err)
		}
		if out.Token != mintToken || out.AppSlug != "example-app" {
			return fmt.Errorf("token %q app_slug %q", out.Token, out.AppSlug)
		}
		if out.Identity == nil || out.Identity.Subject != "agent:"+defBuilder || out.Identity.Source != "assertion" || out.Identity.Grade != "workload" {
			return fmt.Errorf("identity %+v", out.Identity)
		}
		if !strings.Contains(res.Stderr, "mint audit:") || !strings.Contains(res.Stderr, `grade="workload"`) || !strings.Contains(res.Stderr, "agent:"+defBuilder) {
			return fmt.Errorf("no audit line naming subject and grade: %.300s", res.Stderr)
		}
		return nil
	}
}

func (e *Env) shapeMintOtherRole(ctx context.Context) error {
	f, err := e.newMintFixture(true)
	if err != nil {
		return err
	}
	defer f.close()
	assignment, err := e.assertionAssignment(ctx)
	if err != nil {
		return err
	}
	res, err := e.runMint(ctx, f, []string{assignment}, false, "merger")
	if err != nil {
		return err
	}
	if res.Code == 0 || res.Stdout != "" {
		return fmt.Errorf("a builder assertion minted merger (exit %d, stdout %.100q)", res.Code, res.Stdout)
	}
	if !strings.Contains(res.Stderr, "merger") || !strings.Contains(res.Stderr, "builder") {
		return fmt.Errorf("refused, but not naming both roles: %.300s", res.Stderr)
	}
	return nil
}

// shapeMintConfigured is the live-path proof that a deployment with no
// assertion configured is untouched: the configured provider and
// entitled_identities mint, --json has no identity member, and stderr is silent.
func (e *Env) shapeMintConfigured(ctx context.Context) error {
	f, err := e.newMintFixture(false)
	if err != nil {
		return err
	}
	defer f.close()
	res, err := e.runMint(ctx, f, nil, false, "builder")
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("mint exit %d: %.300s", res.Code, res.Stderr)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return fmt.Errorf("mint did not print JSON: %w", err)
	}
	if _, has := raw["identity"]; has || raw["token"] != mintToken || len(raw) != 3 {
		return fmt.Errorf("output members %v", raw)
	}
	if res.Stderr != "" {
		return fmt.Errorf("stderr is not empty: %.300s", res.Stderr)
	}
	return nil
}

// shapeMintForged changes the payload of a delivered assertion so it no longer
// matches its signature: mint must refuse, not mint and not fall back.
func (e *Env) shapeMintForged(ctx context.Context) error {
	f, err := e.newMintFixture(true)
	if err != nil {
		return err
	}
	defer f.close()
	assignment, err := e.assertionAssignment(ctx)
	if err != nil {
		return err
	}
	dir := strings.TrimPrefix(assignment, identityDirEnv+"=")
	file := filepath.Join(dir, "identity.jwt")
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		return fmt.Errorf("delivered file is not a compact JWS")
	}
	tampered := parts[0] + "." + flipFirst(parts[1]) + "." + parts[2]
	if err := os.Remove(file); err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(tampered+"\n"), 0o600); err != nil {
		return err
	}
	res, err := e.runMint(ctx, f, []string{assignment}, false, "builder")
	if err != nil {
		return err
	}
	if res.Code == 0 || res.Stdout != "" {
		return fmt.Errorf("a tampered assertion minted (exit %d, stdout %.100q)", res.Code, res.Stdout)
	}
	if !strings.Contains(res.Stderr, "signature_invalid") && !strings.Contains(res.Stderr, "malformed") {
		return fmt.Errorf("refused, but not as an assertion failure: %.300s", res.Stderr)
	}
	return nil
}
