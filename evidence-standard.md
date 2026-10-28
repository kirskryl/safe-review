# Evidence standard

Mark a finding **confirmed** only with a precise code location and unsafe data flow, a reachable vulnerable dependency with advisory ID, a redacted read-only command result, or a non-destructive local reproduction.

Mark **likely** when the static evidence is strong but a precondition is unverified. Mark **needs validation** for scanner output or incomplete access. State the missing evidence. Do not call a scanner hit exploitable on its own.

Reports may include a secret file path, type, permissions, and masked presence status. Never include values, full hashes of low-entropy secrets, full tokens, private keys, cookies, or session IDs. Filter output through `scripts/redact.py` before copying it into a report. Do not use production for destructive probes.
