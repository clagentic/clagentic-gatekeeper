// Command gatekeeper mints role-scoped GitHub App installation tokens.
//
//	gatekeeper mint --role builder [--repo owner/name] [--config path] [--json]
//
// All deployment-specific values come from config.yaml (see config.example.yaml).
// No org names, hostnames, paths, or identities are hardcoded here.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2amint"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/broker"
	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mint":
		if err := runMint(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "mint-a2a":
		if err := runMintA2A(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "serve", "issue-session", "issue-child":
		run := map[string]func([]string) error{
			"serve": runServe, "issue-session": runIssueSession, "issue-child": runIssueChild,
		}[os.Args[1]]
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "hook":
		os.Exit(runHook(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	case "hooks-install", "render-agent":
		run := map[string]func([]string, io.Writer) error{
			"hooks-install": runHooksInstall, "render-agent": runRenderAgent,
		}[os.Args[1]]
		if err := run(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("clagentic-gatekeeper dev")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gatekeeper <command> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  mint --role <role> [--repo <owner/name>] [--config <path>] [--json]")
	fmt.Fprintln(os.Stderr, "  mint-a2a --audience <audience> [--config <path>] [--json]")
	fmt.Fprintln(os.Stderr, "  serve [--socket <path>] [--config <path>]   (linux only)")
	fmt.Fprintln(os.Stderr, "  issue-session [--socket <path>] [--definition <name>] [--origin <origin>] [--runtime] [--runtime-id <id>] [--runtime-version <v>] [--json]")
	fmt.Fprintln(os.Stderr, "  issue-child [--socket <path>] [--parent-token-file <path>] --agent-type <name> --agent-id <id> [--json]")
	fmt.Fprintln(os.Stderr, "  hook claude-code <session-start|subagent-start|pre-tool-use-bash|subagent-stop|user-prompt-submit> --socket <path> --state-dir <dir> [--mode warn|enforce]   (reads the hook JSON on stdin)")
	fmt.Fprintln(os.Stderr, "  hook process --socket <path> [--definition <name>] [--origin <origin>]   (prints "+hookEnvName+"=<dir> for a launcher's child)")
	fmt.Fprintln(os.Stderr, "  hooks-install --runtime claude-code --settings <path> --socket <path> [--mode warn|enforce] [--remove] [--dry-run]")
	fmt.Fprintln(os.Stderr, "  render-agent --runtime claude-code [--definitions-dir <dir>] <definition>")
	fmt.Fprintln(os.Stderr, "  version")
}

// mintResult is the OPTIONAL structured mint output emitted with --json
// (lr-dbe5d4). It is strictly additive: the default (no --json) output is
// unchanged — a bare token string on stdout — so an existing consumer that
// only ever reads that line never observes this type at all. AppSlug is the
// broker-VERIFIED App slug internal/mint's App-slug gate already checked
// against the role's configured expectation before minting; it is never the
// configured expectation itself, and it is empty when the role has no
// App-slug binding configured (verification gate off for that role).
//
// Identity is present only when the deployment configures the assertion
// provider, so a deployment without it keeps byte-identical --json output.
type mintResult struct {
	Token     string        `json:"token"`
	ExpiresAt string        `json:"expires_at"`
	AppSlug   string        `json:"app_slug,omitempty"`
	Identity  *mintIdentity `json:"identity,omitempty"`
}

// mintIdentity is the attested identity a token was minted for. Grade is empty
// for an identity that does not come from an assertion.
type mintIdentity struct {
	Subject string `json:"subject"`
	Source  string `json:"source"`
	Grade   string `json:"grade,omitempty"`
}

// runMint parses flags, builds the service graph, and mints a token.
func runMint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	roleName := fs.String("role", "", "role to mint (required)")
	repo := fs.String("repo", "", "repository to scope the token to (owner/name); omit for all installed repos")
	cfgPath := fs.String("config", "config.yaml", "path to config.yaml")
	jsonOutput := fs.Bool("json", false, "emit {token, expires_at, app_slug} JSON instead of the bare token string; app_slug is the broker-verified value, empty when the role has no App-slug binding configured; identity {subject, source, grade} is added when attestation.assertion is configured")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *roleName == "" {
		return fmt.Errorf("--role is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// An identity-only config (issuer-only deployment) has no roles section.
	// Say so before building anything that could reach a broker or GitHub.
	if len(cfg.Roles) == 0 {
		return fmt.Errorf("mint: minting is not configured: config %s has no roles section (github, broker and roles are needed to mint; an identity-only config serves assertions only)", *cfgPath)
	}

	registry := roles.NewRegistry()
	for name, rc := range cfg.Roles {
		if len(rc.Permissions) == 0 {
			// No custom permissions: let the reference role definition win.
			// The registry already seeds reference roles; only add config-only roles.
			continue
		}
		// Config supplies an explicit permission set: convert and override.
		perms := make(map[string]roles.Permission, len(rc.Permissions))
		for k, v := range rc.Permissions {
			perms[k] = roles.Permission(v)
		}
		registry.Add(name, perms)
	}

	bindings := make(map[string]mint.RoleBinding, len(cfg.Roles))
	for name, rc := range cfg.Roles {
		bindings[name] = mint.RoleBinding{
			AppIDPath:          rc.AppIDPath,
			InstallationIDPath: rc.InstallationIDPath,
			PrivateKeyPath:     rc.PrivateKeyPath,
			EntitledIdentities: rc.EntitledIdentities,
			MinGrade:           rc.MinGrade,
			AppSlug:            rc.AppSlug,
			AppSlugPath:        rc.AppSlugPath,
		}
	}

	// Startup validation: a config role that has a broker binding but neither
	// config-supplied permissions nor a reference definition cannot be resolved
	// at mint time. Catch it here — before any broker call — so the user gets a
	// clear config error rather than a confusing "unknown role" at runtime.
	for name, rc := range cfg.Roles {
		if len(rc.Permissions) == 0 && !roles.IsReference(name) {
			return fmt.Errorf("config error: role %q has a broker binding but no permissions defined", name)
		}
		if !mint.ValidMinGrade(rc.MinGrade) {
			return fmt.Errorf("config error: role %q has min_grade %q; it must be workload or harness", name, rc.MinGrade)
		}
	}

	br, err := broker.New(broker.Config{
		Type:     cfg.Broker.Type,
		Endpoint: cfg.Broker.Endpoint,
		Auth:     cfg.Broker.Auth,
	})
	if err != nil {
		// Config-level error — print to stderr and exit 2.
		fmt.Fprintf(os.Stderr, "broker: %v\n", err)
		os.Exit(2)
	}

	// Attestation chain resolves the ATTESTED invoking identity for the
	// mint-time entitlement check (tome #700, layer (2)->(3)). A bare install
	// with no attestation config still gets a resolver; the built-in OS-user
	// layer (c) is appended only under the deprecated allow_os_user opt-in,
	// so a caller no layer identifies is refused rather than skipped.
	//
	// ResolveSidecars merges the legacy single `attestation.sidecar` block
	// (back-compat) ahead of the `attestation.sidecars` list, so a
	// deployment can carry more than one independent sidecar namespace
	// (e.g. a per-session namespace for a lead process and a per-spawn
	// namespace for its subagents) in a single resolver chain.
	sidecarCfgs := cfg.Attestation.ResolveSidecars()
	chainSidecars := make([]attestation.SidecarConfig, len(sidecarCfgs))
	for i, sc := range sidecarCfgs {
		chainSidecars[i] = attestation.SidecarConfig{
			Dir:           sc.Dir,
			FilePrefix:    sc.FilePrefix,
			SessionIDEnv:  sc.SessionIDEnv,
			IdentityField: sc.IdentityField,
		}
	}

	// The assertion provider is tried before every other layer when configured
	// and is nil otherwise, which leaves the chain exactly as it was.
	assertionProvider, err := buildAssertionProvider(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		os.Exit(2)
	}

	resolver, err := attestation.NewChain(attestation.ChainConfig{
		Assertion: assertionProvider,
		Configured: attestation.ConfiguredConfig{
			Type:   attestation.ConfiguredType(cfg.Attestation.Configured.Type),
			Source: cfg.Attestation.Configured.Source,
		},
		Sidecars:   chainSidecars,
		OmitOSUser: !cfg.Attestation.OSUserAllowed(),
		OSUserWarn: func(id attestation.Identity) {
			fmt.Fprintf(os.Stderr, "attestation: warning: identity %q was resolved by the deprecated OS-user provider; configure attestation.assertion or attestation.configured, then remove attestation.allow_os_user\n", id.Subject)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		os.Exit(2)
	}

	// Domain-aware MISS policy (lr-2a8653): the deployment's documented
	// convention (docs/SIDECAR-READ-CONTRACT.md section 2,
	// docs/SETUP.md#3-multiple-sidecar-namespaces-in-one-deployment) is
	// spawn-first — the FIRST entry of attestation.sidecars is the
	// per-spawn namespace, checked before any session namespace. That first
	// entry is scoped into its own Resolver as DomainResolver.PerSpawn, so a
	// per-spawn attestation MISS can be required to fail closed rather than
	// falling through to a later (e.g. session) entry in chainSidecars,
	// without reordering or duplicating the shared chain itself.
	domainResolver := &attestation.DomainResolver{Chain: resolver}
	if len(chainSidecars) > 0 {
		perSpawnProvider, err := attestation.NewSidecarProvider(chainSidecars[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "attestation: build per-spawn resolver: %v\n", err)
			os.Exit(2)
		}
		if perSpawnProvider != nil {
			// A spawned subagent's assertion is delivered to it directly, so
			// the assertion is tried first here too; an unset delivery then
			// falls to the per-spawn sidecar and a MISS there still refuses.
			perSpawn := []attestation.Provider{perSpawnProvider}
			if assertionProvider != nil {
				perSpawn = []attestation.Provider{assertionProvider, perSpawnProvider}
			}
			domainResolver.PerSpawn = attestation.NewResolver(perSpawn...)
		}
	}

	// mintDomain names which MISS policy applies to THIS invocation
	// (lr-2a8653): if the per-spawn namespace's own session-id env var is
	// set in this process's environment, a per-spawn harness is active and
	// this invocation is expected to have its own per-spawn sidecar file —
	// so a MISS there must fail closed (DomainLocalSubagent) rather than
	// silently resolving to whatever a lower-priority provider (e.g. the
	// session sidecar) attests, which — inside a spawned subagent process —
	// is the PARENT session's identity, not the subagent's own. When the
	// per-spawn env var is unset, no per-spawn harness is active for this
	// invocation (the common case for a lead/director session, which has no
	// per-spawn sidecar of its own by design, lr-86779f) and DomainLocal
	// preserves today's session-sidecar fallback behavior unchanged. This
	// reads the same env var sidecarProvider.Resolve itself checks for its
	// own MISS — no new config, no new CLI flag, no new source of truth.
	mintDomain := attestation.DomainLocal
	if len(chainSidecars) > 0 && chainSidecars[0].SessionIDEnv != "" {
		if os.Getenv(chainSidecars[0].SessionIDEnv) != "" {
			mintDomain = attestation.DomainLocalSubagent
		}
	}

	svc := mint.Service{
		APIBase:        cfg.GitHub.APIBase,
		TTL:            time.Duration(cfg.Token.TTLMinutes) * time.Minute,
		Roles:          registry,
		Broker:         br,
		Bindings:       bindings,
		DomainResolver: domainResolver,
		// The audit line goes to stderr so stdout stays the token contract. It
		// is emitted only for assertion identities (see mint.Service.Audit).
		Audit: func(ev mint.AuditEvent) {
			fmt.Fprintf(os.Stderr, "mint audit: subject=%q source=%q grade=%q issuer=%q role=%q permitted=%v reason=%q\n",
				ev.Subject, ev.Source, ev.Grade, ev.Issuer, ev.Role, ev.Permitted, ev.Reason)
		},
	}

	var repos []string
	if *repo != "" {
		bare, err := parseRepoName(*repo)
		if err != nil {
			return fmt.Errorf("--repo %q: %w", *repo, err)
		}
		repos = []string{bare}
	}

	res, err := svc.MintAttributed(context.Background(), mintDomain, *roleName, repos)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	token := res.Token

	if *jsonOutput {
		out := mintResult{
			Token:     token.Value,
			ExpiresAt: token.ExpiresAt.Format(time.RFC3339),
			AppSlug:   token.AppSlug,
		}
		if assertionProvider != nil {
			out.Identity = &mintIdentity{Subject: res.Identity.Subject, Source: res.Identity.Source, Grade: res.Identity.Grade}
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}

	// Default output is unchanged from before this field existed: the bare
	// token string, nothing else. A consumer that never passes --json is
	// unaffected by AppSlug's existence (lr-dbe5d4 backward-compat contract).
	fmt.Println(token.Value)
	return nil
}

// a2aMintResult is the structured mint-a2a output emitted with --json. The
// default (no --json) output is the bare token string, mirroring runMint's
// existing contract. Subject is the caller entity id the peer-facing
// token's own "sub" claim resolves to (internal/a2atoken.Token.Subject) —
// gatekeeper's own audit-facing echo of what OpenBao issued, not a claim it
// invents or restates onto the wire token itself.
type a2aMintResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Subject   string `json:"subject,omitempty"`
}

// runMintA2A parses flags, builds the A2A service graph, and mints a
// peer-facing token through OpenBao's documented JWT login flow: the caller's
// serve-issued identity assertion logs in at the configured auth mount and
// the returned client token requests the identity token.
//
// This command is ADDITIVE and OFF BY DEFAULT: it requires
// config.a2a_provider to be fully configured (config.A2AProviderConfig.
// Enabled()) and attestation.assertion to be configured; a deployment that
// never sets that stanza gets a clear config error here and is completely
// unaffected on the existing `gatekeeper mint` (GitHub-domain) path — see
// docs/SETUP.md for the byte-identical-behavior guarantee this preserves.
func runMintA2A(args []string) error {
	fs := flag.NewFlagSet("mint-a2a", flag.ContinueOnError)
	audience := fs.String("audience", "", "peer audience/scope to request a mint for (required)")
	cfgPath := fs.String("config", "config.yaml", "path to config.yaml")
	jsonOutput := fs.Bool("json", false, "emit {token, expires_at, subject} JSON instead of the bare token string")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *audience == "" {
		return fmt.Errorf("--audience is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if !cfg.A2AProvider.Enabled() {
		return fmt.Errorf("config error: a2a_provider is not configured (endpoint and auth_mount are both required together); see config.example.yaml")
	}

	// The OpenBao JWT mount logs in with the caller's identity assertion, so
	// the assertion provider is the only identity source mint-a2a can use. A
	// sidecar or configured identity carries no assertion to present.
	assertionProvider, err := buildAssertionProvider(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		os.Exit(2)
	}
	if assertionProvider == nil {
		return fmt.Errorf("config error: mint-a2a logs in at the OpenBao JWT mount with the caller's identity assertion; attestation.assertion must be configured (write `assertion: {}` to trust the local serve issuer); see config.example.yaml")
	}

	// mint-a2a ALWAYS resolves under attestation.DomainA2A: the A2A/remote-
	// facing mint domain never falls through to a lower-priority provider on a
	// per-spawn miss (docs/SETUP.md, lr-2ca216). The assertion is delivered to
	// each spawn directly, so it is both the whole chain and the per-spawn
	// resolver.
	resolver, err := attestation.NewChain(attestation.ChainConfig{
		Assertion:  assertionProvider,
		OmitOSUser: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		os.Exit(2)
	}
	domainResolver := &attestation.DomainResolver{
		Chain:    resolver,
		PerSpawn: attestation.NewResolver(assertionProvider),
	}

	policy := a2apolicy.NewPolicyFromEntries(cfg.A2AMapping)

	authRoleForRole := make(map[string]string, len(cfg.A2AProvider.Roles))
	oidcRoleForRole := make(map[string]string, len(cfg.A2AProvider.Roles))
	for role, rc := range cfg.A2AProvider.Roles {
		authRoleForRole[role] = rc.AuthRole
		oidcRoleForRole[role] = rc.OIDCRole
	}

	svc := a2amint.Service{
		DomainResolver:  domainResolver,
		Policy:          policy,
		Endpoint:        cfg.A2AProvider.Endpoint,
		AuthMount:       cfg.A2AProvider.AuthMount,
		AuthRoleForRole: authRoleForRole,
		OIDCRoleForRole: oidcRoleForRole,
		// Audit: gatekeeper's own audit record of the mint decision
		// (caller identity, resolved role, requested audience, parent
		// session id) — printed to stderr so it never contaminates stdout
		// (the token/JSON output contract) and is still capturable by any
		// log-collecting harness. OpenBao's own audit device remains the
		// mint-of-record for the issuance leg itself.
		//
		// ev.Reason is already bounded/redacted at the source
		// (a2amint.Service.Mint's auditReason helper): a refusal originating
		// from an a2atoken.TransportError (an OpenBao HTTP call) carries only
		// that error's own message, bounded to a2atoken.maxRawBodyExcerpt
		// (currently 200 bytes) on both the parsed-envelope and raw-fallback
		// paths, never a raw third-party response body — so this Fprintf
		// performs no additional filtering of its own. Note the %q verb below
		// is not itself a bound: it escapes newlines/control bytes (Go's
		// strconv.Quote semantics), which closes any log/terminal-injection
		// concern for this sink, but a %q-quoted control-heavy string can run
		// roughly 4x its input length — a 200-byte-bounded Reason can still
		// print up to ~800 bytes here. That expansion is accounted for, not a
		// gap: it is bounded (by maxRawBodyExcerpt transitively), just not to
		// exactly 200 bytes at this exact call site.
		Audit: func(ev a2amint.AuditEvent) {
			fmt.Fprintf(os.Stderr, "a2a mint audit: identity=%q role=%q audience=%q parent_session_id=%q permitted=%v reason=%q\n",
				ev.Identity, ev.Role, ev.Audience, ev.ParentSessionID, ev.Permitted, ev.Reason)
		},
	}

	token, err := svc.Mint(context.Background(), *audience)
	if err != nil {
		return fmt.Errorf("mint-a2a: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(a2aMintResult{
			Token:     token.Value,
			ExpiresAt: token.ExpiresAt.Format(time.RFC3339),
			Subject:   token.Subject,
		})
	}

	fmt.Println(token.Value)
	return nil
}

// parseRepoName accepts a repository identifier in "owner/name" or bare "name"
// form and returns the bare repository name.
//
// GitHub's POST /app/installations/{id}/access_tokens `repositories` field
// expects bare names ("clagentic-directory"), not "owner/name" — the
// installation is already org-scoped via the installation ID. The CLI flag
// deliberately accepts "owner/name" so callers don't need to strip the owner.
//
// Rules:
//   - "" is rejected: caller must pass a non-empty value or omit --repo.
//   - Bare "name" (no '/') passes through unchanged.
//   - "owner/name" (exactly one '/') returns the name segment.
//   - Any other form (leading '/', trailing '/', multiple '/') is rejected.
func parseRepoName(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("repository name must not be empty")
	}
	idx := strings.IndexByte(s, '/')
	if idx == -1 {
		// Bare name — no owner prefix, pass through.
		return s, nil
	}
	// Ensure exactly one '/'.
	if strings.Count(s, "/") != 1 {
		return "", fmt.Errorf("repository must be 'owner/name' or bare 'name'; got %q", s)
	}
	owner := s[:idx]
	name := s[idx+1:]
	if owner == "" {
		return "", fmt.Errorf("owner segment must not be empty in %q", s)
	}
	if name == "" {
		return "", fmt.Errorf("name segment must not be empty in %q", s)
	}
	return name, nil
}
