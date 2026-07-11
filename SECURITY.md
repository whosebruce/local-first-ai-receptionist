# Security Policy

## Reporting a vulnerability

Open a GitHub security advisory on this repository (preferred), or open an
issue titled "SECURITY" without exploit details and a maintainer will follow
up privately. Please do not publish working exploits against live deployments
before a fix is available.

## What this project guarantees (by design, enforced in code and tests)

- **No tools for contacts.** No code path gives an inbound contact access to
  a terminal, browser, files, mail, calendar, payments, memory, or any agent
  tool. Tier-2 model calls contain only a role policy, bounded context, and
  the quoted message; the request never includes a `tools` field.
- **Deterministic authorization.** Promotion, downgrade, block, and Discord
  intake approvals are exact-grammar commands from the configured owner
  identity, bound to lead ID + keyed fingerprint, replay-resistant, and
  resolve-once. Model output can never change trust state.
- **Fail-closed defaults.** Outbound disabled until manually enabled; images
  rejected before download without a functioning vision classifier; classifier
  errors delete and escalate; unknown webhook signatures → 401; unknown
  correlation tokens → no state write; overlay drift → no changes applied.
- **Local-only model traffic.** Loopback always; private-LAN only with an
  explicit opt-in; globally routable endpoints are refused in code.
- **No raw identities at rest or in logs.** Contacts are tracked by lead ID +
  keyed HMAC fingerprint; alerts and logs carry masked addresses; thread and
  channel names never contain raw identity.
- **HMAC on every internal webhook** with locally generated secrets (0600),
  constant-time comparison, and no secret material in any log or error.

## What this project does NOT guarantee

- **iMessage transport:** end-to-end encrypted between Apple endpoints, but
  decrypted at your Mac; from that point security is your machine's security.
- **Discord:** channels are permission-private, not end-to-end encrypted.
  Discord (the company) can see channel contents.
- **Local models are constrained, not infallible.** The architecture limits
  what a confused or manipulated model can *do* (nothing but words), not what
  it can *say*. Bounded, redacted, capped output reduces — not eliminates —
  the chance of an embarrassing reply.
- **The vision classifier is a best-effort screen.** A sensitive image the
  classifier misdescribes can be retained for up to the retention window.
  The fail-closed contract bounds the damage; it does not make the classifier
  smart.
- **This is not a compliance certification** (HIPAA, PCI, SOC 2, etc.). If
  you have regulatory obligations, get a professional assessment.

## Hardening checklist for deployments

See `THREAT-MODEL.md` for the full model. Minimum: keep the state directory
0700 and secrets 0600 (the service warns otherwise), bind loopback unless you
need LAN, use the provided systemd sandbox (`IPAddressDeny=any` plus narrow
allows), keep outbound disabled until you have piloted with a consenting
contact, and re-run `scripts/verify.sh` after every update.
