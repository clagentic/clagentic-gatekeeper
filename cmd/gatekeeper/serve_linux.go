//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// runServe starts the Identity Assertion issuer, logging to the process stderr.
func runServe(args []string) error { return serve(args, os.Stderr) }

// lockedWriter serialises writes so the startup lines and the server's own log
// lines, written from different goroutines, never interleave inside a line.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// retiredJWKs is the retired_keys section as the issuer's key type.
func retiredJWKs(in []config.RetiredKeyConfig) []identity.JWK {
	out := make([]identity.JWK, len(in))
	for i, k := range in {
		out[i] = identity.JWK{Kty: k.Kty, Crv: k.Crv, Kid: k.Kid, Alg: k.Alg, Use: k.Use, X: k.X, Y: k.Y}
	}
	return out
}

// serve is runServe with its log destination as a parameter, so a caller can
// capture what serve writes without touching a process global. It reads only
// the identity section: a config without github, broker or roles serves
// normally.
func serve(args []string, stderr io.Writer) error {
	log := &lockedWriter{w: stderr}
	logf := func(format string, a ...any) { fmt.Fprintf(log, format+"\n", a...) }

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
		fmt.Fprintln(log, w)
	}
	mode, err := identity.ParseSocketMode(cfg.Identity.SocketMode)
	if err != nil {
		return err
	}
	ic := cfg.Identity
	sock, err := pickSocket(*socket, cfg, identity.DefaultSocketPath)
	if err != nil {
		return err
	}
	// The hook and CLI commands are this same binary. A peer running it is a
	// transient helper and is bound to the runtime above it, not to itself.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("identity: resolve own executable: %w", err)
	}
	issuer, err := identity.NewIssuer(identity.Settings{
		Issuer: ic.Issuer, SocketPath: sock, KeyPath: ic.KeyPath, Alg: ic.Alg,
		JWKSPath: ic.JWKSPath, RuntimeRoles: ic.RuntimeRoles, DefinitionsDir: ic.DefinitionsDir,
		DelegableRoles: ic.DelegableRoles, SpawnRoot: ic.SpawnRoot,
		SessionTTL:  time.Duration(ic.SessionTTLSeconds) * time.Second,
		HelperExe:   strings.TrimSuffix(self, " (deleted)"),
		RetiredKeys: retiredJWKs(ic.RetiredKeys),
	})
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer issuer.Close()
	// Nothing is published until this process owns the socket: a second serve
	// that Listen refuses must not overwrite the key set the live one published.
	l, err := identity.ListenLogged(sock, mode, logf)
	if err != nil {
		return fmt.Errorf("identity: listen: %w", err)
	}
	if ic.JWKSPath != "" {
		if err := issuer.Keys.WriteJWKS(ic.JWKSPath); err != nil {
			// serve never unlinks a path, its own socket included: the service
			// manager owns the socket directory and clears it when the unit stops
			// (docs/SETUP.md, "Running under a service manager").
			l.Close()
			return fmt.Errorf("identity: write jwks_path: %w (the socket %s was created and is left for the service manager to remove)", err, sock)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf("identity: serving iss=%s kid=%s on %s", issuer.Issuer, issuer.Keys.Kid(), sock)
	return (&identity.Server{Issuer: issuer, Logf: logf}).Serve(ctx, l)
}
