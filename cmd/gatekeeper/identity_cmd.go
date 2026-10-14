package main

import (
	"encoding/json"
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

// socketFor resolves the socket path: the flag, then identity.socket_path,
// then the built-in default.
func socketFor(flagValue string, cfg *config.Config) string {
	switch {
	case flagValue != "":
		return flagValue
	case cfg != nil && cfg.Identity.SocketPath != "":
		return cfg.Identity.SocketPath
	}
	return identity.DefaultSocketPath
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

func runIssueSession(args []string) error {
	fs := flag.NewFlagSet("issue-session", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default "+identity.DefaultSocketPath+")")
	definition := fs.String("definition", "", "agent definition name; its roles become the ceiling")
	origin := fs.String("origin", "", "human, scheduled, loop, trigger or agent")
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
	out, err := identity.Client{Socket: socketFor(*socket, nil)}.IssueSession(req)
	if err != nil {
		return fmt.Errorf("issue-session: %w", err)
	}
	return printIssued(os.Stdout, out, *asJSON)
}

func runIssueChild(args []string) error {
	fs := flag.NewFlagSet("issue-child", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default "+identity.DefaultSocketPath+")")
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
	out, err := identity.Client{Socket: socketFor(*socket, nil)}.IssueChild(identity.ChildRequest{
		ParentToken: strings.TrimSpace(string(raw)), AgentType: *agentType, AgentID: *agentID,
	})
	if err != nil {
		return fmt.Errorf("issue-child: %w", err)
	}
	if err := reportNarrowing(os.Stderr, out); err != nil {
		return fmt.Errorf("issue-child: write narrowing report: %w", err)
	}
	return printIssued(os.Stdout, out, *asJSON)
}
