# Repository governance (consumer-side, not minted by Gatekeeper)

Gatekeeper mints tokens. It does not configure your repositories. But the tokens
only produce a credible "built → reviewed → merged by separate actors" trail if the
target repo enforces it. This doc is the reference ruleset a consumer applies.

On GitHub Free, all of the following are available on **public repositories** at no
cost (and unavailable on private repos under a free org). This is why the public
release path and the governance model align.

## Default-branch ruleset

Apply a branch ruleset to the default branch:

- Require a pull request before merging.
- Require at least one approving review.
- Require review from Code Owners (point `CODEOWNERS` at the reviewer identity).
- Require status checks to pass.
- Restrict who can push the branch — name **only** the merger identity.
- Block force pushes.
- Dismiss stale approvals on new commits.

## CODEOWNERS

Point required review at the reviewer App so its approval is mandatory:

```
# .github/CODEOWNERS
*   @your-org/reviewer-team-or-app
```

## Verified commits (optional)

For builder commits to show the green **Verified** badge, the builder must create
commits through GitHub-managed write paths (the Contents API / web flow) with no
custom committer. Local `git commit` + push will not be auto-verified. This is
plan-independent and works on Free.

## Why this lives here and not in code

Ruleset and CODEOWNERS configuration is per-repo, per-installer, and changes with
the consumer's trust model. Baking it into Gatekeeper would couple a generic
token-minter to one org's governance choices. Gatekeeper provides the tokens; the
consumer provides the gate.
