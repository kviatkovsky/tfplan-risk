# ADR 0002: Rule engine design

- Status: accepted
- Date: 2026-11-05

## Context

We need ~20 rules now and more later (other providers, custom rules), each
small and independently testable, with per-rule configuration, severity
overrides and suppressions that stay auditable.

## Decision

Pipeline: `plan.Parse` → `engine.Run` (rules → overrides → ignores → score →
gate) → `report.Renderer` → exit code.

**Model.** `plan.Change` is our own minimal struct (see ADR 0005). Two-action
replacements collapse to `ActionReplace` with a `ReplaceOrder`
(delete-before-create / create-before-destroy). Sensitive leaves are replaced
with `plan.Redacted` during parsing, so no rule or renderer can leak them.

**Two rule interfaces.**

```go
type Rule interface {
    Meta() Meta
    Evaluate(c plan.Change) []Finding     // one resource change
}
type PlanRule interface {
    Meta() Meta
    EvaluatePlan(p *plan.Plan) []Finding  // whole plan, e.g. "> N deletes"
}
```

Rules are pure functions of their input: no I/O, no context, no logging.
`Meta` (ID, title, category, max severity, checked attributes, example,
suggestion) feeds `tfplan-risk rules`, `explain` and the generated catalogue,
so documentation cannot drift from code.

**Optional capabilities** instead of a fat interface:

- `Configurable.Configure(decode func(any) error)` - the rule declares a
  typed options struct; the config layer decodes YAML into it with unknown
  keys rejected. Rules do not import the YAML library.
- `StatefulTypesExtender` - receives top-level `stateful_types_extra`.

**Registry.** Explicit construction (`builtin.New()`), no `init()` side
effects. Each call returns fresh rule instances because options mutate them.
IDs follow `TPR-<AREA>-NNN` and are validated at registration.

**Engine semantics.**

- Rules see managed resources only, never `no-op` or data-source reads.
- A severity override replaces the severity of every finding of that rule.
- Ignores match address and rule ID globs (`*`, `?`; brackets are literal so
  `aws_x.y["k"]` works) and require a `reason`. Suppressed findings are kept
  in the result (and JSON) but excluded from score and gate.
- Unknown rule IDs, options for non-configurable rules and ignore patterns
  that match no rule are config errors, not silent no-ops.
- Findings are sorted by severity, address, rule ID for stable output.

## Alternatives

- **OPA/Rego policies.** Very flexible and already used for Terraform
  (conftest). But Rego is a second language for contributors, slower to
  test table-driven, and a heavy dependency. Kept on the roadmap as an
  *additional* source of custom rules, not the core.
- **Single interface with `Evaluate(plan)`** for all rules. Simpler registry,
  but every rule would re-implement iteration and filtering.
- **Global registration via `init()`.** Convenient, but hidden state makes
  tests order-dependent and configuration leak between engines.

## Consequences

- Adding a rule = one file + table-driven test + one line in `builtin.New`.
- Rules cannot see each other's findings; cross-rule grouping (e.g. collapse
  tag-only changes) is a renderer concern.
- Rule evaluation is single-threaded; parse + evaluate is I/O-bound on input
  size and benchmarked separately.
