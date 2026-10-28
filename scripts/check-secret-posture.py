#!/usr/bin/env python3
"""Masked secret posture check — never prints secret values."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

SECRET_NAME_RE = re.compile(
    r"(?i)^(.*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL).*)$"
)
ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

CANDIDATE_GLOBS = (
    ".env",
    ".env.*",
    "*credentials*.json",
    "*service_account*.json",
    "*telegram-proxy.env",
)


def _mode_oct(path: Path) -> str:
    try:
        return oct(path.stat().st_mode & 0o777)[2:]
    except OSError:
        return "?"


def _world_bits(mode: int) -> dict[str, bool]:
    return {
        "world_readable": bool(mode & stat.S_IROTH),
        "world_writable": bool(mode & stat.S_IWOTH),
    }


def _fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def _scan_env_file(path: Path) -> dict:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    keys: list[dict] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = ENV_LINE_RE.match(line)
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        # strip optional quotes without retaining value
        present = bool(val.strip().strip("'\""))
        interesting = bool(SECRET_NAME_RE.match(name)) or present
        if not interesting:
            continue
        keys.append(
            {
                "name": name,
                "status": "present" if present else "absent",
                "type": "env_var",
                "fingerprint": _fingerprint(f"{name}=".encode() + (b"1" if present else b"0")),
            }
        )
    st = path.stat()
    return {
        "path": str(path),
        "status": "present",
        "type": "env_file",
        "mode": _mode_oct(path),
        **_world_bits(st.st_mode),
        "file_fingerprint": _fingerprint(raw),
        "keys": keys,
        # never include values
    }


def _scan_binaryish(path: Path) -> dict:
    raw = path.read_bytes()
    st = path.stat()
    return {
        "path": str(path),
        "status": "present",
        "type": "secret_file",
        "mode": _mode_oct(path),
        **_world_bits(st.st_mode),
        "file_fingerprint": _fingerprint(raw),
    }


def collect(root: Path) -> list[dict]:
    found: list[Path] = []
    for pattern in CANDIDATE_GLOBS:
        found.extend(root.rglob(pattern))
    # de-dupe, skip huge trees
    uniq = sorted({p.resolve() for p in found if p.is_file()})
    out: list[dict] = []
    for p in uniq[:200]:
        # skip node_modules / venv noise
        parts = set(p.parts)
        if parts & {"node_modules", ".venv", "venv", ".git"}:
            continue
        try:
            if p.name.startswith(".env") or p.name.endswith(".env"):
                out.append(_scan_env_file(p))
            else:
                out.append(_scan_binaryish(p))
        except OSError as e:
            out.append({"path": str(p), "status": "error", "error": str(e)})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    results = collect(root)
    if args.json:
        json.dump({"root": str(root), "secrets": results}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"root: {root}")
        if not results:
            print("secrets: none found")
        for r in results:
            flags = []
            if r.get("world_readable"):
                flags.append("WORLD_READ")
            if r.get("world_writable"):
                flags.append("WORLD_WRITE")
            flag_s = (" [" + ",".join(flags) + "]") if flags else ""
            print(
                f"{r.get('type')} mode={r.get('mode')} "
                f"fp={r.get('file_fingerprint', '-')}{flag_s} path={r.get('path')}"
            )
            for k in r.get("keys") or []:
                print(f"  key {k['name']} status={k['status']} fp={k['fingerprint']}")
        print("note: secret VALUES were not printed")
    # exit 2 if world-readable/writable secrets
    bad = any(r.get("world_readable") or r.get("world_writable") for r in results)
    return 2 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
