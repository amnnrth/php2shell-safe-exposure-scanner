# Security Policy

## Intended use

This project is intended for authorized defensive exposure triage. It deliberately avoids exploit payloads and vulnerability-triggering probes. It is not designed to validate exploitability.

## Reporting a security issue in this project

Please do not post secrets, target hostnames, IP addresses, scan reports, credentials, or an unpatched vulnerability affecting a third party in a public issue. Use GitHub's **Report a vulnerability** feature on the repository if private vulnerability reporting is enabled. Otherwise, contact the repository maintainers through a private channel listed on the repository profile.

When reporting an issue, include the affected version/commit, reproduction steps that do not target third-party systems, expected behavior, observed behavior, and potential impact. Redact organization-specific data.

## Scope boundaries

- Security reports about this scanner's code and packaging are in scope.
- Requests to add RCE payloads, exploit code, credential attacks, destructive testing, or stealth/evasion functionality are out of scope for this project.
- Findings discovered on external targets should be reported to the asset owner under the owner's coordinated disclosure process, not in this repository.

## Supported versions

Security fixes are provided on a best-effort basis for the latest published release. Users should keep dependencies patched and review changes before running scans.
