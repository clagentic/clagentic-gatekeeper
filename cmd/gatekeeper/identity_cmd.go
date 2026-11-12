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

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// identityEnvDir is the delivery variable of the contract's section 6.
const identityEnvDir = "CLAGENTIC_IDENTITY_DIR"

// errNoSocket is what a client that must not guess answers when nothing names
// the socket.
var errNoSocket = errors.New("no socket: pass --socket, or --config with identity.socket_path set")

// pickSocket is the one resolution order every command that names the issuer
// socket uses: the flag, then identity.socket_path, then fallback. An empty
// fallback means no default, and the answer is errNoSocket. A flag goes through
// the same check identity.socket_path gets at config load: absolute, and short
// enough for a unix socket.
func pickSocket(flagValue string, cfg *config.Config, fallback string) (string, error) {
	switch {
	case flagValue != "":
		if err := config.CheckSocketPath("--socket", flagValue); err != nil {
			return "", err
		}
		return flagValue, nil
	case cfg != nil && cfg.Identity.SocketPath != "":
		return cfg.Identity.SocketPath, nil
	case fallback != "":
		return fallback, nil
	}
	return "", errNoSocket
}

// resolveSocket is pickSocket for a command that reads the config only to find
// the socket: cfgPath empty means no config.
func resolveSocket(flagValue, cfgPath, fallback string) (string, error) {
	var cfg *config.Config
	if flagValue == "" && cfgPath != "" {
		var err error
		if cfg, err = loadConfig(cfgPath, os.Stderr); err != nil {
			return "", fmt.Errorf("load config: %w", err)
		}
	}
	return pickSocket(flagValue, cfg, fallback)
}

// printIssued writes the bare token, or the full response with --json.
// A failed write is returned so the command exits non-zero: a caller that reads
// an empty or truncated token must not see success.
func printIssued(w io.Writer, out *identity.Issued, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(out)
	}
	_, err := fmt.Fprintln(w, out.Token)
	return err
}

// reportNarrowing makes a policy-narrowed child visible without --json.
func reportNarrowing(w io.Writer, out *identity.Issued) error {
	if out.Narrowed == nil {
		return nil
	}
	for _, step := range out.Narrowed.Steps {
		if _, err := fmt.Fprintf(w, "narrowed by %s: dropped roles %s\n", step.Policy, strings.Join(step.Dropped, ",")); err != nil {
			return err
		}
	}
	return nil
}

func runIssueSession(args []string) error { return issueSession(args, os.Stdout) }

// issueSession is runIssueSession with its output as a parameter, so a caller
// can read what it prints without touching a process global.
func issueSession(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("issue-session", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default identity.socket_path from --config, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	definition := fs.String("definition", "", "agent definition name; its roles become the ceiling")
	origin := fs.String("origin", "", "scheduled, loop, trigger, agent or driven (human is refused for sessions)")
	runtime := fs.Bool("runtime", false, "declare a runtime session (informational: every assertion is a workload assertion)")
	runtimeID := fs.String("runtime-id", "", "runtime id; must equal the attested one when given")
	runtimeVersion := fs.String("runtime-version", "", "runtime version label")
	asJSON := fs.Bool("json", false, "emit the full response as JSON instead of the bare token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req := identity.SessionRequest{Definition: *definition, Origin: *origin}
	if *runtime || *runtimeID != "" || *runtimeVersion != "" {
		req.Runtime = &identity.RuntimeDecl{ID: *runtimeID, Version: *runtimeVersion}
	}
	sock, err := resolveSocket(*socket, *cfgPath, identity.DefaultSocketPath)
	if err != nil {
		return fmt.Errorf("issue-session: %w", err)
	}
	out, err := identity.Client{Socket: sock}.IssueSession(req)
	if err != nil {
		return fmt.Errorf("issue-session: %w", err)
	}
	return printIssued(stdout, out, *asJSON)
}

func runIssueChild(args []string) error { return issueChild(args, os.Stdout, os.Stderr) }

// issueChild is runIssueChild with its outputs as parameters.
func issueChild(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("issue-child", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default identity.socket_path from --config, then "+identity.DefaultSocketPath+")")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	parentFile := fs.String("parent-token-file", "", "file holding the parent token (default $"+identityEnvDir+"/"+identity.DeliveryFile+")")
	agentType := fs.String("agent-type", "", "definition name of the child (required)")
	agentID := fs.String("agent-id", "", "identifier of this spawn (required)")
	asJSON := fs.Bool("json", false, "emit the full response as JSON instead of the bare token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentType == "" || *agentID == "" {
		return fmt.Errorf("--agent-type and --agent-id are required")
	}
	path := *parentFile
	if path == "" {
		dir := os.Getenv(identityEnvDir)
		if dir == "" {
			return fmt.Errorf("no parent token: pass --parent-token-file or set %s", identityEnvDir)
		}
		path = filepath.Join(dir, identity.DeliveryFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read parent token: %w", err)
	}
	sock, err := resolveSocket(*socket, *cfgPath, identity.DefaultSocketPath)
	if err != nil {
		return fmt.Errorf("issue-child: %w", err)
	}
	out, err := identity.Client{Socket: sock}.IssueChild(identity.ChildRequest{
		ParentToken: strings.TrimSpace(string(raw)), AgentType: *agentType, AgentID: *agentID,
	})
	if err != nil {
		return fmt.Errorf("issue-child: %w", err)
	}
	if err := reportNarrowing(stderr, out); err != nil {
		return fmt.Errorf("issue-child: write narrowing report: %w", err)
	}
	return printIssued(stdout, out, *asJSON)
}
