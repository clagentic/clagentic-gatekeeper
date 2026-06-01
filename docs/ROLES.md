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

Roles are data, not hardcoded enums where avoidable. A consumer with a different
trust model (e.g. a single `maintainer` role, or a fourth `releaser` role) defines
it by:

1. Registering an App with the desired permission set.
2. Adding a `roles.<name>` block to `config.yaml` with the broker paths.
3. Declaring the role's permission narrowing (the table above, as data) so
   Gatekeeper narrows the minted token correctly.

The three shipped roles are the reference model, not a hard limit.
