// Command gatekeeper mints role-scoped GitHub App installation tokens.
//
//	gatekeeper mint --role builder --repo owner/name
//
// All deployment-specific values come from config.yaml (see config.example.yaml).
// No org names, hostnames, paths, or identities are hardcoded here.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mint":
		// TODO(build): parse --role/--repo, load config.yaml, build the
		// roles.Registry (reference + config roles), construct the broker via
		// broker.New, assemble mint.Service, call Mint, print the token.
		fmt.Fprintln(os.Stderr, "gatekeeper mint: not yet implemented")
		os.Exit(1)
	case "version":
		fmt.Println("clagentic-gatekeeper (dev)")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gatekeeper mint --role <role> --repo <owner/name>")
}
