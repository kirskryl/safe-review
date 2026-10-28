---
name: safe-review
description: Evidence-based security audit of a local product, including code, dependencies, secrets posture, runtime configuration, and CI. Use for security audits and pre-deploy reviews.
license: MIT
---

# safe-review

Audit a product and report evidence-backed findings. The audit is read-only. Make fixes only when the user authorizes specific findings.

## Model and reviewer

Use a separate reviewer when the runner supports subagents. Choose the strongest available model other than Astra or Fable, including aliases whose names contain `astra` or `fable`. If it cannot be started, retry once with the next strongest allowed model. Name the model in the final report. If no separate agent is available, perform the audit yourself and disclose that limitation.

## Scope

Default to a local product audit. For a pre-deploy request, include the diff, dependency and deploy configuration. Examine production only when the user explicitly requests and authorizes a read-only check of a named environment. Do not probe, exploit, fuzz, change configuration, restart services, or deploy during an audit.

## Workflow

1. Identify repository root, stack, entry points, assets, trust boundaries, privileged actions, and attacker assumptions. Use `scripts/detect-stack.sh`, `scripts/collect-inventory.sh`, and `scripts/check-secret-posture.py` when relevant.
2. Review applicable controls in [audit-checklist.md](audit-checklist.md). Check code paths, dependency versions, config, CI, and deployment files. Avoid opening secret values unless essential; never place them in output.
3. Apply [evidence-standard.md](evidence-standard.md). Separate confirmed findings from likely issues and unvalidated scanner output. Redact command output with `scripts/redact.py` before including it in a report.
4. Fill [report-template.md](report-template.md), run `scripts/validate-report.py`, and report the verdict, top findings, limitations, and proposed fixes.
5. If the user authorizes specific fixes, change only those items, verify them, and provide a short delta report.

## Verdict

| Evidence | Verdict |
| --- | --- |
| Confirmed Critical | `BLOCKED — Critical` |
| Confirmed High | `UNSAFE — High risk` |
| Confirmed Medium or likely High | `CONDITIONAL — remediation required` |
| Only Low or Informational | `ACCEPTABLE WITH NOTES` |
| Insufficient access or coverage | `INCONCLUSIVE` |

Never print secret values, full tokens, private keys, cookies, or session IDs. A scanner hit without supporting evidence is a hypothesis. Do not claim an unexamined product is secure.
