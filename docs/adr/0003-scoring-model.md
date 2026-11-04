# ADR 0003: Scoring model

- Status: accepted
- Date: 2026-11-05

## Context

Besides the per-finding severity gate we want one number for dashboards and
PR comments: "how risky is this plan?". It must be explainable in one line,
monotonic (more findings never lower the score), bounded, and must not let a
pile of low findings look like one critical data-loss event.

## Decision

```
sum   = Σ weight(severity) over active (non-suppressed) findings
score = round(100 × (1 − e^(−sum / 50)))
```

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 15 |
| medium | 5 |
| low | 1 |
| info | 0 |

Resulting scores:

| Findings | Score |
|---|---|
| 1 low | 2 |
| 1 medium | 10 |
| 1 high | 26 |
| 1 critical | 55 |
| 2 critical | 80 |
| 2 critical + 1 high + 1 medium + 1 low | 87 |
| 20 critical | 100 |

The gate is separate from the score:

- `--fail-on <severity>` (default `critical`, `none` disables): exit 2 if any
  active finding is at or above it.
- `--max-score N` (optional): exit 2 if the score is above N.
- Either condition fails the run. CLI flags override `fail_on` / `max_score`
  in the config file.

## Alternatives

- **Max severity only.** Simple, but cannot distinguish one open port from
  a plan that deletes ten databases.
- **Linear sum capped at 100.** Explainable, but saturates after three
  criticals and offers no diminishing returns.
- **Per-category sub-scores.** More precise, harder to explain and to gate
  on; categories are still available in JSON output.
- **Weights by resource criticality (prod vs. dev).** Needs knowledge we do
  not have in a plan; users express it through ignores and overrides.

## Consequences

- One critical finding alone gives 55; a single high never exceeds 26, so
  `--max-score 50` roughly means "fail on any critical or several highs".
- Weights live in `engine.Weights` and are documented here and in the
  README; changing them is a behavior change that needs a new ADR.
- Suppressed findings never affect the score.
