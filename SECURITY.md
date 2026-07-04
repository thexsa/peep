# Security Policy

## Supported Versions

| Version        | Supported |
| -------------- | --------- |
| Latest release | ✅ Yes    |
| Older versions | ❌ No     |

Only the latest release receives security fixes. If you're on an older version, please update before reporting.

## Reporting a Vulnerability

Report security issues by opening a GitHub Issue with the `security` label:

👉 [https://github.com/thexsa/peep/issues](https://github.com/thexsa/peep/issues)

Please include:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Affected version** of peep
- **Impact assessment** — what can an attacker achieve?

## Response

We'll do our best to acknowledge reports within **72 hours**. Fix timelines depend on severity — critical issues get priority, lower-severity issues land in the next release.

## Disclosure

We follow **coordinated disclosure**. Once a fix is ready, we'll work with you on a reasonable timeline before any public disclosure. Please don't disclose vulnerabilities publicly before we've had a chance to address them.

## Scope

peep is a local diagnostic tool — it has no server component, no daemon, and no network listeners. The primary attack surface is **malicious TLS responses** from hosts you choose to scan (e.g., crafted certificates, unexpected protocol behavior).

If you find a way for a remote host to cause peep to crash, hang, or behave unexpectedly through a TLS response, that's in scope.
