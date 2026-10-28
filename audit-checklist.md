# Audit checklist

Use only controls relevant to the product. Record a finding with evidence or list the control under checks passed.

- Entry points, authentication, authorization, tenancy and admin actions
- Input handling: injection, SSRF, path traversal, XSS, CSRF and open redirects
- Secret storage and file permissions, logging, cryptography and session handling
- Dependency versions, lockfiles, advisories and supply-chain scripts
- Docker, systemd, reverse proxy, listener and CORS configuration
- CI and deploy permissions, backups and data handling
- Product-specific risks revealed by discovery

Severity: Critical for demonstrated remote code execution or usable credential exposure; High for reachable authorization bypass or exploitable injection; Medium for plausible defense gaps; Low for limited hardening gaps; Informational for observations.
