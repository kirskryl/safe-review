#!/usr/bin/env python3
"""Redact secrets and PII from text streams for safe-review."""
from __future__ import annotations

import re
import sys

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(api[_-]?key|secret|password|token|passwd|authorization)\s*[=:]\s*['\"]?([^\s'\"]{8,})"),
     r"\1=***REDACTED***"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer ***REDACTED***"),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"), "***TG_TOKEN***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "***PRIVATE_KEY***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "***JWT***"),
    (re.compile(r"(?i)(cookie|set-cookie)\s*[:=]\s*[^\s;]+"), r"\1=***REDACTED***"),
    (re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I), "***EMAIL***"),
    (re.compile(r"\+?\d[\d\-\s()]{9,}\d"), "***PHONE***"),
]


def redact_text(s: str) -> str:
    out = s
    for pat, repl in PATTERNS:
        out = pat.sub(repl, out)
    return out


def main() -> int:
    data = sys.stdin.read()
    sys.stdout.write(redact_text(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
