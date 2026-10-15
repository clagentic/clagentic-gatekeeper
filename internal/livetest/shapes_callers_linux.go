//go:build linux

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// This file holds one mint shape per caller of `gatekeeper mint` found by
// searching the consumers, each in both configurations: with no assertion
// configured (the output must be exactly what it was before the assertion
// provider existed) and with the assertion provider configured and an assertion
// delivered. A form is the caller's own argv (role, repository, config and
// output flags), its identity source and its broker. Names are the forms'
// own; the caller each stands for is listed in docs/LIVE-TEST.md.

const callerRepo = "example/example-repo"

// callerForm is the way one caller invokes mint.
type callerForm struct {
	id   string
	role string
	// repo is passed as --repo when set.
	repo string
	// json is passed as --json.
	json bool
	// noConfig leaves out --config, so the config is the working directory's.
	noConfig bool
	broker   brokerKind
	// refused marks a form whose role the config does not know: mint must refuse
	// it before it resolves an identity or reads a credential.
	refused bool
}

func (f callerForm) argv(cfgPath string) []string {
	args := []string{"mint", "--role", f.role}
	if f.repo != "" {
		args = append(args, "--repo", f.repo)
	}
	if !f.noConfig {
		args = append(args, "--config", cfgPath)
	}
	if f.json {
		args = append(args, "--json")
	}
	return args
}

// definitionFor is the invented definition whose assertion carries role.
func definitionFor(role string) string {
	switch role {
	case "reviewer":
		return defLead
	case "merger", "security", "reader":
		return defOps
	}
	return defBuilder
}

func callerForms() []callerForm {
	return []callerForm{
		// A configured token helper: the session environment is inherited and no
		// repository is forwarded.
		{id: "token-helper-push", role: "builder"},
		{id: "token-helper-push-structured", role: "builder", json: true},
		{id: "token-helper-review", role: "reviewer"},
		{id: "token-helper-merge", role: "merger"},
		{id: "token-helper-close-pr", role: "merger"},
		{id: "token-helper-post-merge", role: "merger"},
		{id: "token-helper-git-host-api", role: "reader", noConfig: true},
		{id: "token-helper-acquire", role: "reader"},
		{id: "token-helper-health-probe", role: "example-probe", refused: true},
		// A script that executes the binary itself with the repository and the
		// secret store's login in its environment.
		{id: "direct-exec-builder", role: "builder", repo: callerRepo, broker: brokerOpenBao},
		{id: "direct-exec-reviewer", role: "reviewer", repo: callerRepo, broker: brokerOpenBao},
		{id: "direct-exec-merger", role: "merger", repo: callerRepo, broker: brokerOpenBao},
		{id: "direct-exec-security", role: "security", repo: callerRepo, broker: brokerOpenBao},
		{id: "direct-exec-reader", role: "reader", repo: callerRepo, broker: brokerOpenBao},
		{id: "direct-exec-security-pr-reader", role: "security", repo: callerRepo, broker: brokerOpenBao},
	}
}

func (e *Env) callerShapes() []shape {
	var out []shape
	for _, f := range callerForms() {
		for _, assertion := range []bool{false, true} {
			out = append(out, shape{name: "mint-caller/" + f.id + "/" + configName(assertion), run: e.shapeCaller(f, assertion)})
		}
	}
	// A daemon that passes no identity at all: only the OS-user provider can
	// answer, and only while it is allowed.
	for _, assertion := range []bool{false, true} {
		for _, allowed := range []bool{true, false} {
			name := "mint-caller/daemon-no-identity-os-user-" + map[bool]string{true: "allowed", false: "refused"}[allowed] + "/" + configName(assertion)
			out = append(out, shape{name: name, run: e.shapeNoIdentity(assertion, allowed)})
		}
	}
	return out
}

func configName(assertion bool) string {
	if assertion {
		return "assertion"
	}
	return "no-assertion"
}

func (e *Env) shapeCaller(f callerForm, assertion bool) func(context.Context) error {
	return func(ctx context.Context) error {
		fx, err := e.newCallerFixture(fixtureSpec{assertion: assertion, sidecar: !assertion, broker: f.broker, cwdConfig: f.noConfig})
		if err != nil {
			return err
		}
		defer fx.close()
		env := append([]string{}, fx.env...)
		def := definitionFor(f.role)
		if assertion {
			assignment, err := e.assertionAssignmentFor(ctx, def)
			if err != nil {
				return err
			}
			env = append(env, assignment)
		}
		res, err := e.gk(ctx, runOpts{Env: env, Dir: fx.cwd}, f.argv(fx.cfgPath)...)
		if err != nil {
			return err
		}
		if f.refused {
			return checkRefused(res, fx, "")
		}
		if err := checkMinted(f, res, assertion, def); err != nil {
			return err
		}
		return checkScope(f, fx)
	}
}

// checkRefused requires a refusal that printed no token and reached for no
// credential. wantStderr, when set, must appear in the reason.
func checkRefused(res procResult, fx *callerFixture, wantStderr string) error {
	if res.Code == 0 || res.Stdout != "" {
		return fmt.Errorf("a refused mint was not refused (exit %d, stdout %.100q)", res.Code, res.Stdout)
	}
	if res.Stderr == "" || !strings.Contains(res.Stderr, wantStderr) {
		return fmt.Errorf("refused without the expected reason %q: %.300s", wantStderr, res.Stderr)
	}
	if n := len(fx.stub.exchangeBodies()); n != 0 || fx.stub.loginCount() != 0 || fx.stub.readCount() != 0 {
		return fmt.Errorf("a refused mint still reached the credential store or the git host (%d exchanges, %d logins, %d reads)", n, fx.stub.loginCount(), fx.stub.readCount())
	}
	return nil
}

// checkMinted checks a successful mint's stdout and stderr against the
// configuration it ran under.
func checkMinted(f callerForm, res procResult, assertion bool, def string) error {
	if res.Code != 0 {
		return fmt.Errorf("mint exit %d: %.300s", res.Code, res.Stderr)
	}
	if !f.json {
		// The default output is the bare token and nothing else, in either
		// configuration: a consumer that reads one line never sees the identity.
		if res.Stdout != mintToken+"\n" {
			return fmt.Errorf("stdout is %.100q, want the bare token and a newline", res.Stdout)
		}
	} else {
		var raw map[string]any
		if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
			return fmt.Errorf("mint did not print JSON: %w", err)
		}
		if raw["token"] != mintToken || raw["app_slug"] != "example-app" {
			return fmt.Errorf("output members %v", raw)
		}
		if exp, _ := raw["expires_at"].(string); exp == "" {
			return fmt.Errorf("no expires_at in %v", raw)
		}
		id, has := raw["identity"].(map[string]any)
		switch {
		case !assertion && (has || len(raw) != 3):
			return fmt.Errorf("a deployment with no assertion configured printed %v, want exactly token, expires_at and app_slug", raw)
		case assertion && (id["subject"] != "agent:"+def || id["source"] != "assertion" || id["grade"] != "workload"):
			return fmt.Errorf("identity %v", raw["identity"])
		}
	}
	if !assertion {
		if res.Stderr != "" {
			return fmt.Errorf("stderr is not empty with no assertion configured: %.300s", res.Stderr)
		}
		return nil
	}
	for _, want := range []string{"mint audit:", "permitted=true", `grade="workload"`, "agent:" + def} {
		if !strings.Contains(res.Stderr, want) {
			return fmt.Errorf("the audit line lacks %q: %.300s", want, res.Stderr)
		}
	}
	return nil
}

// checkScope requires the token request to name the repository exactly when the
// caller passed one.
func checkScope(f callerForm, fx *callerFixture) error {
	bodies := fx.stub.exchangeBodies()
	if len(bodies) != 1 {
		return fmt.Errorf("%d token requests reached the git host, want 1", len(bodies))
	}
	scoped := strings.Contains(bodies[0], `"repositories":["example-repo"]`)
	if (f.repo != "") != scoped {
		return fmt.Errorf("token request %.200s does not match --repo %q", bodies[0], f.repo)
	}
	if f.broker == brokerOpenBao && fx.stub.loginCount() == 0 {
		return fmt.Errorf("the secret store login was never made")
	}
	return nil
}

// shapeNoIdentity is a caller that passes no identity: no sidecar, no
// assertion delivered, nothing in the environment but the broker. The OS-user
// provider answers while allowed, with a warning, and the mint is refused when
// it is not.
func (e *Env) shapeNoIdentity(assertion, allowed bool) func(context.Context) error {
	return func(ctx context.Context) error {
		// The secret store broker makes the refusal's "no credential read" claim
		// observable; the environment broker would not.
		fx, err := e.newCallerFixture(fixtureSpec{assertion: assertion, osUser: allowed, broker: brokerOpenBao})
		if err != nil {
			return err
		}
		defer fx.close()
		res, err := e.gk(ctx, runOpts{Env: fx.env}, "mint", "--role", "builder", "--config", fx.cfgPath)
		if err != nil {
			return err
		}
		if !allowed {
			return checkRefused(res, fx, "resolve attested identity")
		}
		if res.Code != 0 || res.Stdout != mintToken+"\n" {
			return fmt.Errorf("the OS-user provider did not mint (exit %d, stdout %.100q): %.300s", res.Code, res.Stdout, res.Stderr)
		}
		if !strings.Contains(res.Stderr, "warning") || !strings.Contains(res.Stderr, "deprecated OS-user provider") {
			return fmt.Errorf("an OS-user mint did not warn: %.300s", res.Stderr)
		}
		if strings.Contains(res.Stderr, "mint audit:") {
			return fmt.Errorf("an OS-user identity was audited as an assertion: %.300s", res.Stderr)
		}
		return nil
	}
}

// runtimeMintShapes run mint inside a subagent of a real agent runtime, in the
// foreground and the background, in both configurations: the identity comes from
// the delivery the hook made for that agent, or from the sidecar selected by the
// runtime's own environment.
func (e *Env) runtimeMintShapes() []shape {
	var out []shape
	for _, background := range []bool{false, true} {
		for _, assertion := range []bool{false, true} {
			kind := map[bool]string{false: "foreground", true: "background"}[background]
			name := runtimePrefix + "claude-code/" + kind + "-subagent-mint/" + configName(assertion)
			out = append(out, shape{name: name, run: e.runtimeMintShape(name, background, assertion)})
		}
	}
	return out
}

func (e *Env) runtimeMintShape(name string, background, assertion bool) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := e.runtimeSetup(ctx); err != nil {
			return err
		}
		// The file broker keeps the credentials out of the runtime's environment.
		fx, err := e.newCallerFixture(fixtureSpec{assertion: assertion, sidecar: !assertion, broker: brokerFile})
		if err != nil {
			return err
		}
		defer fx.close()
		command := e.Bin + " mint --role builder --config " + fx.cfgPath
		step := "Wait for it in the foreground."
		if background {
			step = "Start it in the background (run_in_background true). Then run the command sleep 20, up to five times, until the subagent's result has arrived."
		}
		// The command is quoted so the sentence's own punctuation is never taken
		// for part of a path.
		prompt := driverPreamble + "Use the " + defBuilder + " subagent with this prompt: Run this exact command with the Bash tool, without the quotes, and reply with its output only: '" + command + "'. " + step + " Then reply with the word done."
		return e.runtimeShape(ctx, runtimeShape{
			name:   name,
			prompt: func(*Env) string { return prompt },
			check: func(_ *Env, r *runtimeRun) error {
				if !strings.Contains(r.stream, mintToken) {
					return retryable{fmt.Errorf("the subagent's mint result was not printed")}
				}
				audited := strings.Contains(r.stream, "mint audit: subject=") && strings.Contains(r.stream, "permitted=true")
				if assertion && !audited {
					return fmt.Errorf("the subagent minted, but not from its delivered assertion (no audit line)")
				}
				if !assertion && (strings.Contains(r.stream, "mint audit:") || strings.Contains(r.stream, "OS-user")) {
					return fmt.Errorf("a deployment with no assertion configured printed assertion or OS-user output")
				}
				return nil
			},
		}, fx.env)
	}
}
