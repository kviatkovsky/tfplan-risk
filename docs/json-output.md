# JSON output (`--format json`)

Stable, versioned report for automation. `version` is bumped only on breaking
changes (removed/renamed fields, changed types or meaning). New fields may be
added at any time; consumers must ignore unknown fields.

## Schema version 1

```jsonc
{
  "version": 1,
  "tool": { "name": "tfplan-risk", "version": "v0.1.0" },
  "plan": {
    "format_version": "1.2",         // Terraform JSON plan format
    "terraform_version": "1.17.1"
  },
  "summary": {
    "score": 87,                     // 0-100, see docs/adr/0003-scoring-model.md
    "max_severity": "critical",      // null when there are no active findings
    "changes": {                     // managed resources only; keys present when > 0
      "create": 3, "update": 2, "replace": 1, "delete": 1, "forget": 0, "no-op": 12
    },
    "findings": {                    // active findings per severity; all keys present
      "critical": 2, "high": 2, "medium": 1, "low": 0, "info": 0
    },
    "suppressed": 1                  // findings matched by an `ignore` entry
  },
  "gate": {
    "fail_on": "critical",           // null when disabled (none)
    "max_score": null,               // null when not set
    "failed": true,                  // true <=> exit code 2
    "reason": "2 finding(s) at or above critical"   // omitted when not failed
  },
  "findings": [                      // sorted: severity desc, address, rule_id
    {
      "rule_id": "TPR-DATA-001",
      "severity": "critical",        // critical | high | medium | low | info
      "category": "data-loss",       // data-loss | security | availability | cost | hygiene
      "address": "aws_db_instance.main",   // "" for plan-level findings
      "action": "replace",           // create | update | replace | delete | forget | "" (plan-level)
      "message": "stateful resource replaced because ...",
      "suggestion": "Snapshot or back up the data first. ...",
      "suppressed": false,
      "suppress_reason": "..."       // only when suppressed
    }
  ]
}
```

Sensitive values never appear: they are redacted to `(sensitive)` while the
plan is parsed.
