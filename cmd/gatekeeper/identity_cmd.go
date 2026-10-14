package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
func printIssued(out *identity.Issued, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	fmt.Println(out.Token)
	return nil
}

// reportNarrowing makes a policy-narrowed child visible without --json.
func reportNarrowing(out *identity.Issued) {
	if out.Narrowed == nil {
		return
	}
	for _, step := range out.Narrowed.Steps {
		fmt.Fprintf(os.Stderr, "narrowed by %s: dropped roles %s\n", step.Policy, strings.Join(step.Dropped, ","))
	}
}

func runIssueSession(args []string) error {
	fs := flag.NewFlagSet("issue-session", flag.ContinueOnError)
	socket := fs.String("socket", "", "unix socket of the server (default "+identity.DefaultSocketPath+")")
	definition := fs.String("definition", "", "agent definition name; its roles become the ceiling")
	origin := fs.String("origin", "", "human, scheduled, loop, trigger or agent")
	runtime := fs.Bool("runtime", false, "declare a runtime session (an operator gets a workload assertion, not a human one)")
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
	return printIssued(out, *asJSON)
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
	reportNarrowing(out)
	return printIssued(out, *asJSON)
}
