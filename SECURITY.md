# Security Policy

ANI (Adversarial Neural Inspector) is itself a security tool. If you find a security issue in ANI itself — not in a target application you scanned with it — please follow this policy.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** Public disclosure gives attackers a head start on a fix.

Report privately to:

- **Email**: abhirupguhakolkata@gmail.com
- **GitHub**: use [GitHub's private vulnerability reporting](https://github.com/fir3storm/ANI/security/advisories/new) on the repository's Security tab.

Please include:

1. A short title and the affected component (CLI, sidebar, reporting, etc.).
2. Steps to reproduce, or a proof-of-concept if the issue requires a real target.
3. The impact you observed (XSS, credential leak, RCE, etc.).
4. The version of ANI and the Python / Node / Firefox versions you tested on.
5. Whether the issue requires authentication or specific permissions to exploit.

You can encrypt sensitive details with this maintainer's PGP key if needed; if not, plain text is fine for an initial report and we can move to a signed channel from there.

## What to expect

- **Acknowledgement**: within 7 days of the report.
- **Triage**: within 14 days, with a severity assessment (CVSS or qualitative) and a fix plan.
- **Fix timing**: critical issues target a patch release within 30 days; high within 90 days; lower-severity issues are bundled into the next regular release.
- **Credit**: credited in the release notes unless you ask to remain anonymous.
- **Coordinated disclosure**: a 90-day disclosure deadline is the default. We will agree on an extension if a fix needs more time.

## Supported versions

Only the latest release on `master` receives security patches. Older versions are not patched; please upgrade.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No — please upgrade |

## Out of scope

These are issues in the *targets* ANI scans, not in ANI itself, and should not be reported here:

- Vulnerabilities found in third-party AI chat applications you scanned with ANI.
- Issues in third-party dependencies (Playwright, Typer, Rich, etc.) — report upstream.
- Reports of ANI "succeeding" against a chat app you own — that is ANI working as designed; remediate your target.

## Hardening features

ANI ships with several built-in protections. Do not disable them when reporting issues — flag the case where they don't apply.

- HTML reports use Jinja2 autoescape and a `Content-Security-Policy` meta tag.
- Sidebar results are built with `createElement` + `textContent` (no `innerHTML`).
- Credentials at rest are Fernet-encrypted (`auth_profiles/`, `sessions/`).
- Network-captured headers are redacted before any serialized output.
- The deprecated `--cookie` flag emits a warning at use; prefer `--cookie-file` or `ANI_AUTH_COOKIE`.

## Security audits

ANI is developed and reviewed with:

- A regression test suite of 46 tests including explicit XSS-regression, encryption, and PII-redaction tests.
- Manual code review for any new payload, browser, or auth surface.
- No telemetry, no auto-update, no remote code fetch at runtime.

If you spot a gap, please report it through the channels above.
