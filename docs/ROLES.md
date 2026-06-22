# Roles and per-role GitHub App permissions

Gatekeeper ships three generic roles. Each maps to one GitHub App registered with
exactly the installation permissions below. The token Gatekeeper mints for a role
is narrowed to these permissions at mint time — defense in depth on top of whatever
the App itself was granted.

## builder

Purpose: author work. Pushes feature branches, opens and updates PRs.

| GitHub permission   | Level   | Note                                              |
|---------------------|---------|---------------------------------------------------|
| `contents`          | `write` | Feature branches only. The default-branch ruleset must bar pushes to the protected branch. |
| `pull_requests`     | `write` | Open / update PRs. Does not include merge.        |
| `issues`            | `write` | Optional; for linking / commenting.               |

Builder **must not** be able to merge. Enforcement is two-layer: the merge happens
via a separate API surface the merger token holds, and the default-branch ruleset
restricts pushers to the merger identity.

## reviewer

Purpose: review. Submits PR reviews (approve / request changes) and comments.

| GitHub permission   | Level   | Note                                              |
|---------------------|---------|---------------------------------------------------|
| `pull_requests`     | `write` | Required to submit the `APPROVE` review event.    |
| `contents`          | `read`  | Read the diff under review.                        |

The reviewer App **must be a different App than the builder App**. GitHub forbids an
actor from approving its own PR; a separate reviewer identity is what makes a
required approving review possible at all.

## merger

Purpose: land work. Merges PRs and pushes the default branch.

| GitHub permission   | Level   | Note                                              |
|---------------------|---------|---------------------------------------------------|
| `contents`          | `write` | Including the protected default branch.            |
| `pull_requests`     | `write` | Including the merge action.                        |

The default-branch ruleset's push restriction should name **only** the merger App.

## Adding a custom role

Roles are data, not hardcoded enums. A consumer with a different trust model
(e.g. a `maintainer` between reviewer and merger, or a `releaser` scoped only
to tagging) defines one by:

1. Registering a GitHub App with the desired permission set.
2. Adding a `roles.<name>` block to `config.yaml` with the broker paths for
   that App's credentials.
3. Declaring the role's permission narrowing in the same block.

### Config schema for step 3

```yaml
roles:
  releaser:
    app_id_path: secret/gatekeeper/releaser/app-id
    installation_id_path: secret/gatekeeper/releaser/installation-id
    private_key_path: secret/gatekeeper/releaser/private-key
    permissions:          # optional; omit to use the reference set for this role name
      contents: write     # push release tags / commits
      pull_requests: read # read PR context; does not include merge
```

**Permission keys** are GitHub App permission resource names (e.g. `contents`,
`pull_requests`, `issues`, `deployments`, `checks`, `statuses`). See the
[GitHub Apps permissions documentation](https://docs.github.com/en/rest/apps/apps)
for the full list.

**Permission values** are `read` or `write`.

Gatekeeper mints the token with exactly the permissions declared here,
regardless of what the underlying App was granted. This is the narrowing step;
the App's own grant is the ceiling, but the minted token is narrowed further
to only what the role needs.

### Provider rendering

The permission map in `config.yaml` is provider-neutral. Today Gatekeeper
renders it to the GitHub installation-token `permissions` object (the only
supported provider). Forgejo scope-string rendering (`read:repository`,
`write:issue`, etc.) is added by lr-bb2f without changing this config schema
or the GitHub renderer.

### Reference roles and overrides

The three reference roles (builder/reviewer/merger) are pre-seeded from code.
You may override their permission set in `config.yaml` using the same
`permissions:` block — the config-supplied set wins. Omitting `permissions:`
for a reference role uses the built-in table above.

Note: a role binding (`app_id_path` / `installation_id_path` / `private_key_path`)
with no resolvable permission set (neither a `permissions:` block nor a matching
reference role) is a misconfiguration. Startup validation for this case is tracked
in lr-1b65.
