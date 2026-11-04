# Plan fixtures

Each `<scenario>.json` is the output of `terraform show -json plan.bin` for
`examples/scenarios/<scenario>/`: apply `v1.tf`, switch to `v2.tf`, plan.

| Fixture | Origin |
|---|---|
| `rds-replace.json` | **synthetic** |
| `s3-delete.json` | **synthetic** |
| `sg-open-db-port.json` | **synthetic** |
| `iam-wildcard.json` | **synthetic** |

**Synthetic** fixtures are hand-written to the documented
[Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format)
(`format_version` 1.2: `resource_changes[].change.actions`, `before`, `after`,
`after_unknown`, `before_sensitive`, `after_sensitive`, `replace_paths`,
`action_reason`). They keep only the attributes relevant to the scenario, so
`before`/`after` are smaller than real provider output. The `.tf` files show
the configuration that would produce them.

Rules:

- Account IDs are always `123456789012`; no real ARNs, IDs or secrets.
- Names use neutral prefixes (`demo`, `example`, `myapp`).
