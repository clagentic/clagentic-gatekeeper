//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// runServe starts the Identity Assertion issuer. It reads only the identity
// section: a config without github, broker or roles serves normally.
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket to listen on (default identity.socket_path, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "config.yaml", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.IdentityEnabled() {
		return fmt.Errorf("config error: the identity section is not configured; see config.example.yaml")
	}
	if w := cfg.RemovedIdentityKeysWarning(); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}
	mode, err := identity.ParseSocketMode(cfg.Identity.SocketMode)
	if err != nil {
		return err
	}
	ic := cfg.Identity
	sock := socketFor(*socket, cfg)
	issuer, err := identity.NewIssuer(identity.Settings{
		Issuer: ic.Issuer, SocketPath: sock, KeyPath: ic.KeyPath, Alg: ic.Alg,
		JWKSPath: ic.JWKSPath, RuntimeRoles: ic.RuntimeRoles, DefinitionsDir: ic.DefinitionsDir,
		DelegableRoles: ic.DelegableRoles, SpawnRoot: ic.SpawnRoot,
		SessionTTL: time.Duration(ic.SessionTTLSeconds) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer issuer.Close()
	// Nothing is published until this process owns the socket: a second serve
	// that Listen refuses must not overwrite the key set the live one published.
	l, err := identity.Listen(sock, mode)
	if err != nil {
		return fmt.Errorf("identity: listen: %w", err)
	}
	if ic.JWKSPath != "" {
		if err := issuer.Keys.WriteJWKS(ic.JWKSPath); err != nil {
			// Listen does not unlink on Close, and this process created the
			// socket, so it removes it rather than leave a name nobody serves.
			l.Close()
			os.Remove(sock)
			return fmt.Errorf("identity: write jwks_path: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "identity: serving iss=%s kid=%s on %s\n", issuer.Issuer, issuer.Keys.Kid(), sock)
	return (&identity.Server{Issuer: issuer}).Serve(ctx, l)
}
