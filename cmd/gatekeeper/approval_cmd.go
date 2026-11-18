package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// runApproval dispatches `gatekeeper approval <request|fetch>`.
func runApproval(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: gatekeeper approval request --op <op> --params-digest <sha256> [--summary <text>] | gatekeeper approval fetch --rid <rid>")
	}
	switch args[0] {
	case "request":
		return approvalRequest(args[1:], stdout)
	case "fetch":
		return approvalFetch(args[1:], stdout)
	}
	return fmt.Errorf("approval: unknown command %q; the commands are request and fetch", args[0])
}

// printJSON writes v as one JSON line. A failed write is returned so the command
// exits non-zero: a caller reading an empty reply must not see success.
func printJSON(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

// approvalRequest asks serve to record a pending approval for one operation, in
// the session whose assertion this process holds, and prints the request id,
// its expiry and the phrase the operator types.
func approvalRequest(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("approval request", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default identity.socket_path from --config, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	tokenFile := fs.String("token-file", "", "file holding the session assertion (default $"+identityEnvDir+"/"+identity.DeliveryFile+")")
	op := fs.String("op", "", "name of the operation to approve (required)")
	digest := fs.String("params-digest", "", "SHA-256 of the operation's parameters, 64 hexadecimal characters (required)")
	summary := fs.String("summary", "", "one line shown in the issuer log to say what is being approved")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *op == "" || *digest == "" {
		return errors.New("approval request: --op and --params-digest are required")
	}
	token, err := readSessionToken(*tokenFile)
	if err != nil {
		return fmt.Errorf("approval request: %w", err)
	}
	sock, err := resolveSocket(*socket, *cfgPath, identity.DefaultSocketPath)
	if err != nil {
		return fmt.Errorf("approval request: %w", err)
	}
	out, err := identity.Client{Socket: sock}.RequestApproval(identity.ApprovalRequest{
		Token: token, Op: *op, ParamsDigest: *digest, Summary: *summary,
	})
	if err != nil {
		return fmt.Errorf("approval request: %w", err)
	}
	return printJSON(stdout, out)
}

// approvalFetch returns the signed approval of a granted request. It needs no
// session: any process serve admits may fetch, once.
func approvalFetch(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("approval fetch", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default identity.socket_path from --config, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	rid := fs.String("rid", "", "request id the operator approved (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rid == "" {
		return errors.New("approval fetch: --rid is required")
	}
	sock, err := resolveSocket(*socket, *cfgPath, identity.DefaultSocketPath)
	if err != nil {
		return fmt.Errorf("approval fetch: %w", err)
	}
	out, err := identity.Client{Socket: sock}.FetchApproval(identity.ApprovalFetchRequest{Rid: *rid})
	if err != nil {
		return fmt.Errorf("approval fetch: %w", err)
	}
	return printJSON(stdout, out)
}

// readSessionToken reads the session assertion from the named file, or from the
// delivery directory the environment names.
func readSessionToken(file string) (string, error) {
	path := file
	if path == "" {
		dir := os.Getenv(identityEnvDir)
		if dir == "" {
			return "", fmt.Errorf("no session assertion: pass --token-file or set %s", identityEnvDir)
		}
		path = filepath.Join(dir, identity.DeliveryFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the session assertion: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}
