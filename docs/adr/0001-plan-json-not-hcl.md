# ADR 0001: Analyze the plan JSON, not HCL

- Status: accepted
- Date: 2026-11-05

## Context

Most Terraform security scanners (Checkov, Trivy/tfsec, KICS) analyze HCL
source. They answer "is this configuration acceptable?". Reviewers of a pull
request need a different answer: "what will happen when this is applied?".
Many of the dangerous outcomes are invisible in the source diff:

- A one-line attribute change can force replacement (`storage_encrypted`,
  `identifier`, `engine` on `aws_db_instance`). Only the provider knows which
  attributes are ForceNew; the plan reports it in `replace_paths`.
- Removing a resource block, a module call, or changing `count` to
  `for_each` deletes objects without any visible `destroy` in the code.
- Values come from variables, locals, modules and data sources; HCL tools
  must re-implement Terraform's evaluation to know a CIDR or a policy.
- `-replace`, tainted resources and `replace_triggered_by` cause replacements
  with no source change at all (`action_reason` reports them).

`terraform show -json <planfile>` emits a documented, versioned format
(`format_version` 1.x, backwards compatible within a major version) with
`resource_changes[].change.{actions,before,after,after_unknown,replace_paths}`.

## Decision

The tool reads only the JSON plan. It never parses HCL, never calls cloud
APIs and never needs credentials. Rules reason about the *diff*
(before → after) so that pre-existing state is not reported again on every
plan.

## Alternatives

- **Static HCL analysis.** Works without a plan (no credentials, no state),
  but cannot see ForceNew replacements, deletions from removed blocks, or
  evaluated values. Existing tools already cover it well.
- **Both HCL and plan.** Gives source locations (file:line) but doubles the
  surface area and requires a full HCL evaluator to be correct.
- **Terraform's own `-detailed-exitcode`.** Only says "there are changes".

## Consequences

- The CI job must run `terraform plan`, which needs state and credentials.
  The analyzer itself stays credential-free and costs nothing to run.
- No file/line locations: findings point to resource addresses. SARIF uses
  logical locations (see report docs).
- Some lifecycle settings are not in the plan's `resource_changes`:
  - `prevent_destroy` is not exported. But a successful plan that deletes an
    object proves `prevent_destroy` was not set on it, because Terraform
    fails the plan otherwise.
  - `create_before_destroy` *is* visible for replacements through the action
    order: `["create","delete"]` vs. `["delete","create"]`.
- Values known only after apply appear in `after_unknown`; rules must treat
  them as unknown and never as empty.
- Sensitive values are present in the plan file; the parser redacts them
  using `before_sensitive`/`after_sensitive` before any rule sees them.
