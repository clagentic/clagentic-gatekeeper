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
	"time"

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

	svc := mint.Service{
		APIBase:  cfg.GitHub.APIBase,
		TTL:      time.Duration(cfg.Token.TTLMinutes) * time.Minute,
		Roles:    registry,
		Broker:   br,
		Bindings: bindings,
	}

	var repos []string
	if *repo != "" {
		repos = []string{*repo}
	}

	token, err := svc.Mint(context.Background(), *roleName, repos)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	fmt.Println(token.Value)
	return nil
}
