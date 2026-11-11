package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// errSelfCheckFailed is the exit-status carrier: the lines that say what failed
// are already on stdout.
var errSelfCheckFailed = errors.New("self-check failed")

// selfCheckTimeout bounds the one request to the socket.
const selfCheckTimeout = 5 * time.Second

// firstDifference is the offset of the first byte at which a and b differ, or
// the length of the shorter one when one is a prefix of the other. It is only
// called for unequal inputs.
func firstDifference(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// runSelfCheck proves a running serve is reachable and that the key set it
// serves is the one on disk. The comparison is of bytes and nothing else: serve
// writes jwks_path from the exact bytes it serves, so any difference means the
// file is not what verifiers reading it are told the issuer publishes.
func runSelfCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("self-check", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default identity.socket_path from --config, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path and identity.jwks_path name the socket and the key set file")
	jwksFlag := fs.String("jwks-path", "", "key set file to compare with what the socket serves (default identity.jwks_path from --config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var cfg *config.Config
	if *cfgPath != "" {
		var err error
		if cfg, err = config.Load(*cfgPath); err != nil {
			return fmt.Errorf("self-check: load config: %w", err)
		}
	}
	sock, err := pickSocket(*socket, cfg, identity.DefaultSocketPath)
	if err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	jwksPath := *jwksFlag
	if err := config.CheckAbsPath("--jwks-path", jwksPath); err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	if jwksPath == "" && cfg != nil {
		jwksPath = cfg.Identity.JWKSPath
	}

	served, err := identity.Client{Socket: sock, Timeout: selfCheckTimeout}.FetchJWKSBytes()
	if err != nil {
		fmt.Fprintf(stdout, "socket: unreachable: %v\n", err)
		return errSelfCheckFailed
	}
	fmt.Fprintf(stdout, "socket: reachable (%s)\n", sock)

	if jwksPath == "" {
		fmt.Fprintln(stdout, "jwks: not checked: no key set file is named; pass --config with identity.jwks_path set, or --jwks-path")
		return nil
	}
	fi, err := os.Stat(jwksPath)
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	var onDisk []byte
	if err == nil {
		onDisk, err = os.ReadFile(jwksPath)
	}
	if err != nil {
		fmt.Fprintf(stdout, "jwks: stale: cannot read %s: %v\n", jwksPath, err)
		return errSelfCheckFailed
	}
	if !bytes.Equal(served, onDisk) {
		fmt.Fprintf(stdout, "jwks: stale: the socket serves %d bytes and %s holds %d; they first differ at byte %d\n",
			len(served), jwksPath, len(onDisk), firstDifference(served, onDisk))
		return errSelfCheckFailed
	}
	fmt.Fprintf(stdout, "jwks: fresh (%d bytes, identical to %s)\n", len(served), jwksPath)
	return nil
}
