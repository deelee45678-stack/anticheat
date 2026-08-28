# Security Policy

## Supported versions

Only the latest released line receives security fixes. We recommend tracking the
most recent tag.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, report privately so we can coordinate a fix before public disclosure.
Use one of the following:

- **GitHub private vulnerability reporting** (preferred): open a private security
  advisory from the repository's "Security" tab → "Report a vulnerability".
- **Email**: deelee45678@gmail.com

Include as much of the following as possible:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof-of-concept
- Affected version(s) and build configuration (libbpf / no-libbpf)
- Any suggested mitigation

You will receive an acknowledgment within **3 business days**.

## Disclosure timeline

We follow coordinated disclosure:

1. **Report received** — we acknowledge within 3 business days.
2. **Triage** — we confirm the issue and assess severity within 7 days.
3. **Fix** — we develop and test a patch; we aim to do this within 30 days for
   critical issues, longer for lower severities.
4. **Coordinated release** — we ship a fixed version and credit the reporter
   (with consent) in the advisory and `CHANGELOG.md`.
5. **Public disclosure** — after a fix is available, we publish the advisory.
   We will not disclose before a fix is released without the reporter's consent.

## Hall of Fame

We thank the following researchers for responsibly disclosing issues:

| Researcher        | Vulnerability / area | Date       |
| ----------------- | -------------------- | ---------- |
| _Your name here_  |                      |            |

(Additions are made with the reporter's explicit consent.)
