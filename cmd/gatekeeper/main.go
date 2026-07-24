// Command gatekeeper mints role-scoped GitHub App installation tokens.
//
//	gatekeeper mint --role builder [--repo owner/name] [--config path]
//
// All deployment-specific values come from config.yaml (see config.example.yaml).
// No org names, hostnames, paths, or identities are hardcoded here.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
	fmt.Fprintln(os.Stderr, "  mint --role <role> [--repo <owner/name>] [--config <path>]")
	fmt.Fprintln(os.Stderr, "  version")
}

// runMint parses flags, builds the service graph, and mints a token.
func runMint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	roleName := fs.String("role", "", "role to mint (required)")
	repo := fs.String("repo", "", "repository to scope the token to (owner/name); omit for all installed repos")
	cfgPath := fs.String("config", "config.yaml", "path to config.yaml")

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
