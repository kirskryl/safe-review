#!/usr/bin/env python3
"""Validate a safe-review markdown report has required fields."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

VERDICTS = (
    "BLOCKED — Critical",
    "UNSAFE — High risk",
    "CONDITIONAL — remediation required",
    "ACCEPTABLE WITH NOTES",
    "INCONCLUSIVE",
)

REQUIRED_SECTIONS = (
    "## Verdict",
    "## Scope and limitations",
    "## Threat model",
    "## Findings",
    "## Checks passed",
    "## Proposed actions requiring approval",
)

FINDING_FIELDS = (
    "Confidence:",
    "Location:",
    "Impact:",
    "Evidence:",
    "Safe remediation:",
)


def validate(text: str) -> list[str]:
    errors: list[str] = []
    for sec in REQUIRED_SECTIONS:
        if sec not in text:
            # allow short form for checks passed
            if sec == "## Checks passed" and "## Checks passed / no issue found" in text:
                continue
            errors.append(f"missing section: {sec}")

    if not any(v in text for v in VERDICTS):
        errors.append("missing recognized verdict string")

    # Findings with severity headings must include fields
    finding_headers = list(
        re.finditer(
            r"^###\s+\d+\.\s+(Critical|High|Medium|Low|Informational)\b",
            text,
            re.M,
        )
    )
    if not finding_headers:
        # OK only if explicit empty findings note
        if "No material findings" not in text and "no material findings" not in text.lower():
            # still allow INFORMATIONAL-only via Checks; require explicit statement
            if "## Findings" in text:
                block = text.split("## Findings", 1)[1].split("## ", 1)[0]
                if block.strip() and "no " not in block.lower()[:200]:
                    pass  # soft
    for i, m in enumerate(finding_headers):
        start = m.start()
        nxt = finding_headers[i + 1].start() if i + 1 < len(finding_headers) else len(text)
        chunk = text[start:nxt]
        # Bound by next H2 section (## but not ###)
        h2 = re.search(r"^## (?!#)", chunk, re.M)
        if h2 and h2.start() > 0:
            chunk = chunk[: h2.start()]
        for field in FINDING_FIELDS:
            if field not in chunk:
                errors.append(f"finding '{m.group(0).strip()}' missing {field}")

    # Ban obvious secret dumps
    if re.search(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b", text):
        errors.append("possible raw Telegram token in report")
    if "BEGIN PRIVATE KEY" in text:
        errors.append("private key material in report")
    if re.search(r"(?i)password\s*=\s*['\"]?[^'\"\s*]{8,}", text):
        if "***REDACTED***" not in text and "fingerprint" not in text.lower():
            errors.append("possible raw password assignment in report")

    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    args = ap.parse_args()
    text = Path(args.report).read_text(encoding="utf-8")
    errs = validate(text)
    if errs:
        print("INVALID report:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
