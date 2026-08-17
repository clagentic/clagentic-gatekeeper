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
type mintResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AppSlug   string `json:"app_slug,omitempty"`
}

// runMint parses flags, builds the service graph, and mints a token.
func runMint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	roleName := fs.String("role", "", "role to mint (required)")
	repo := fs.String("repo", "", "repository to scope the token to (owner/name); omit for all installed repos")
	cfgPath := fs.String("config", "config.yaml", "path to config.yaml")
	jsonOutput := fs.Bool("json", false, "emit {token, expires_at, app_slug} JSON instead of the bare token string; app_slug is the broker-verified value, empty when the role has no App-slug binding configured")

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
	// with no attestation config still gets a resolver — the built-in
	// fallback (layer c) is always appended — so entitlement is never
	// silently skipped for lack of configuration.
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

	resolver, err := attestation.NewChain(attestation.ChainConfig{
		Configured: attestation.ConfiguredConfig{
			Type:   attestation.ConfiguredType(cfg.Attestation.Configured.Type),
			Source: cfg.Attestation.Configured.Source,
		},
		Sidecars: chainSidecars,
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
			domainResolver.PerSpawn = attestation.NewResolver(perSpawnProvider)
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
	}

	var repos []string
	if *repo != "" {
		bare, err := parseRepoName(*repo)
		if err != nil {
			return fmt.Errorf("--repo %q: %w", *repo, err)
		}
		repos = []string{bare}
	}

	token, err := svc.MintForDomain(context.Background(), mintDomain, *roleName, repos)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(mintResult{
			Token:     token.Value,
			ExpiresAt: token.ExpiresAt.Format(time.RFC3339),
			AppSlug:   token.AppSlug,
		})
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
// peer-facing token via the B3 attest-and-route mechanism (lr-890fae).
//
// This command is ADDITIVE and OFF BY DEFAULT: it requires
// config.a2a_provider to be fully configured (config.A2AProviderConfig.
// Enabled()); a deployment that never sets that stanza gets a clear config
// error here and is completely unaffected on the existing `gatekeeper mint`
// (GitHub-domain) path — see cmd/gatekeeper's own package doc and
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
		return fmt.Errorf("config error: a2a_provider is not configured (endpoint, assertion_private_key_path, and auth_mount are all required together); see config.example.yaml")
	}

	br, err := broker.New(broker.Config{
		Type:     cfg.Broker.Type,
		Endpoint: cfg.Broker.Endpoint,
		Auth:     cfg.Broker.Auth,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "broker: %v\n", err)
		os.Exit(2)
	}

	// Attestation wiring mirrors runMint's (see that function's comments for
	// the full resolution-order rationale), but mint-a2a ALWAYS resolves
	// under attestation.DomainA2A — the A2A/remote-facing mint domain never
	// falls through to the session sidecar on a per-spawn miss
	// (docs/SETUP.md section 5, lr-2ca216), unlike the GitHub-domain
	// command's per-invocation domain selection.
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

	resolver, err := attestation.NewChain(attestation.ChainConfig{
		Configured: attestation.ConfiguredConfig{
			Type:   attestation.ConfiguredType(cfg.Attestation.Configured.Type),
			Source: cfg.Attestation.Configured.Source,
		},
		Sidecars: chainSidecars,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		os.Exit(2)
	}

	domainResolver := &attestation.DomainResolver{Chain: resolver}
	if len(chainSidecars) > 0 {
		perSpawnProvider, err := attestation.NewSidecarProvider(chainSidecars[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "attestation: build per-spawn resolver: %v\n", err)
			os.Exit(2)
		}
		if perSpawnProvider != nil {
			domainResolver.PerSpawn = attestation.NewResolver(perSpawnProvider)
		}
	}

	policy := a2apolicy.NewPolicyFromEntries(cfg.A2AMapping)

	authRoleForRole := make(map[string]string, len(cfg.A2AProvider.Roles))
	oidcRoleForRole := make(map[string]string, len(cfg.A2AProvider.Roles))
	for role, rc := range cfg.A2AProvider.Roles {
		authRoleForRole[role] = rc.AuthRole
		oidcRoleForRole[role] = rc.OIDCRole
	}

	assertionTTL := time.Duration(cfg.A2AProvider.AssertionTTLSeconds) * time.Second

	svc := a2amint.Service{
		DomainResolver:          domainResolver,
		Policy:                  policy,
		Broker:                  br,
		AssertionPrivateKeyPath: cfg.A2AProvider.AssertionPrivateKeyPath,
		Issuer:                  cfg.A2AProvider.Issuer,
		AssertionTTL:            assertionTTL,
		Endpoint:                cfg.A2AProvider.Endpoint,
		AuthMount:               cfg.A2AProvider.AuthMount,
		AuthRoleForRole:         authRoleForRole,
		OIDCRoleForRole:         oidcRoleForRole,
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
		// that error's own already-bounded message, never a raw third-party
		// response body, so this Fprintf performs no additional filtering of
		// its own — it is not the place third-party content could reach
		// stderr unbounded.
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
