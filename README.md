# tfplan-risk

Terraform plan risk analyzer. Reads `terraform show -json` output, classifies
every resource change by **data-loss**, **security** and **availability**
risk, computes a 0-100 risk score, and reports to humans (terminal, PR comment)
and machines (JSON, SARIF, exit code). It only reads the plan: no cloud API
calls, no credentials, no cost.

```console
$ terraform plan -out=plan.bin
$ terraform show -json plan.bin | tfplan-risk
CRITICAL  aws_db_instance.main  REPLACE  stateful resource replaced because storage_encrypted false -> true forces replacement: the existing aws_db_instance is destroyed and a new, empty one is created -> data loss [TPR-DATA-001]

Plan: 1 to replace.
Risk score: 55/100 (max severity: critical)
FAIL: 1 finding(s) at or above critical
```

> Status: under active development towards v0.1.0. Full documentation,
> rule catalogue and GitHub Action land in follow-up changes.

## Install

```sh
go install github.com/kviatkovsky/tfplan-risk/cmd/tfplan-risk@latest
```

## Usage

```
tfplan-risk [flags] [plan.json|-]      # default reads stdin
tfplan-risk version

  --format table|json      output format (default table; colors only on a TTY)
  --config FILE            config file (default .tfplan-risk.yaml if present)
  --fail-on SEVERITY       critical|high|medium|low|info|none (default critical)
  --max-score N            also fail when the score is above N
  --no-color               disable colors (NO_COLOR is honored too)
  --log-level LEVEL        debug|info|warn|error
  --terraform-bin PATH     convert a binary plan file via `terraform show -json`
```

Exit codes: `0` below threshold, `1` tool error, `2` threshold exceeded.

## Configuration

`.tfplan-risk.yaml` (unknown keys are errors):

```yaml
fail_on: high
max_score: 60
rules:
  TPR-SEC-001:
    severity: medium        # override
    allow_ports: [80, 443]
ignore:
  - address: "module.sandbox.*"   # glob: * and ? only
    rules: ["*"]
    reason: "sandbox is recreated nightly"   # required
stateful_types_extra: ["aws_opensearch_domain"]
```

## Design

- [ADR 0001 - Analyze the plan JSON, not HCL](docs/adr/0001-plan-json-not-hcl.md)
- [ADR 0002 - Rule engine design](docs/adr/0002-rule-engine-design.md)
- [ADR 0003 - Scoring model](docs/adr/0003-scoring-model.md)
- [JSON output schema](docs/json-output.md)

## License

MIT
