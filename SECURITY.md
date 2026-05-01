# Security Policy

## Supported versions

Firefik is pre-release (0.x). Security fixes are applied only to:

| Version | Status | Support window |
|---|---|---|
| Latest minor (e.g. 0.11.x) | Supported | Until next minor ships |
| Previous minor (e.g. 0.10.x) | Security fixes only | 90 days after next minor |
| Older (≤ 0.9.x) | Unsupported | — |

After v1.0 ships, this policy switches to SemVer-style support
(N-1 minor). Until then, assume only the latest minor is supported.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email: `security@<maintainer-domain>` (placeholder — replace with real
contact when publishing). Alternatively, use GitHub's private
vulnerability reporting on the project's Security tab.

Include:

- Affected version(s) and deployment mode (standalone agent, control
  plane, rootful/rootless Docker, Podman).
- Reproduction steps or PoC.
- Impact assessment (what can an attacker achieve?).
- Your disclosure timeline preference.

We aim to:

- Acknowledge receipt within **3 business days**.
- Issue an initial triage + severity within **7 days**.
- Ship a fix within **30 days** for High/Critical, **90 days** for
  Medium/Low (or coordinate a longer embargo if warranted).

## Scope

**In scope:**

- Auth bypass on HTTP API (`FIREFIK_API_TOKEN`, peer-cred, CSRF).
- mTLS / SPIFFE trust-domain enforcement bypass on control-plane.
- Kernel-rule injection via malicious container labels.
- GeoIP database spoofing or signature verification bypass.
- Audit log tampering or silent drop.
- Mini-CA key extraction or unauthorised cert issuance.

**Out of scope:**

- DoS of the firefik agent via legitimately-authenticated but
  high-volume API traffic (use rate-limit env-vars; see
  `docs/security-hardening.md`).
- Rootful Docker escape — that's Docker's trust model, not ours.
- Social engineering / phishing of operators.
- Vulnerabilities in dependencies that don't affect firefik's threat
  model (we track via Dependabot + govulncheck).

## Safe harbour

Good-faith security research that follows this policy will not trigger
legal action from the maintainers.

## CVE assignment

For accepted reports we request CVEs through GitHub's CNA. Reporters
are credited in the fix commit and release notes unless they request
anonymity.
