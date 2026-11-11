package main

import (
	"strings"
	"testing"
)

// github.owner has a reader: a --repo that names another owner is refused
// rather than reduced to its bare name and minted against the wrong org.
func TestRepoForMintChecksTheOwnerAgainstGithubOwner(t *testing.T) {
	for _, c := range []struct {
		name, repo, owner string
		want              string
		wantErr           string
	}{
		{"owner matches", "example-org/example-repo", "example-org", "example-repo", ""},
		{"owner matches without regard to case", "Example-Org/example-repo", "example-org", "example-repo", ""},
		{"owner differs", "other-org/example-repo", "example-org", "", `owner "other-org" is not github.owner "example-org"`},
		{"bare name is not checked", "example-repo", "example-org", "example-repo", ""},
		{"no configured owner is not checked", "other-org/example-repo", "", "example-repo", ""},
		{"a malformed repo is still refused", "a/b/c", "example-org", "", "owner/name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := repoForMint(c.repo, c.owner)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("got %v, want a refusal containing %q", err, c.wantErr)
			case got != c.want:
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
