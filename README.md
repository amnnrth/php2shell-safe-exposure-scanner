# PHP2Shell Safe Exposure Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A defensive, non-exploit scanner to help an organization inventory public signals related to **PHP2Shell**: CVE-2026-109618 and CVE-2026-109619. It performs bounded DNS, TCP-connect, TLS, HTTP `HEAD`/`GET`, and optional wordlist discovery, then produces an Excel triage report.

> [!IMPORTANT]
> **Authorized use only.** Run this tool only against systems you own or have explicit written permission to assess. You are responsible for defining scope, approval, rate limits, data handling, and compliance with applicable laws and contracts. Do not scan third-party systems without authorization.

> [!WARNING]
> This is an **exposure triage aid, not an exploit, penetration test, or definitive vulnerability verdict**. It does not send vulnerability-triggering payloads. Public-only results cannot prove that a backend PHP runtime is affected or fixed. Use authenticated asset/package inventory and the current vendor advisory to make remediation decisions.

## What it does

- Resolves target names and records DNS outcomes.
- Checks a configurable list of TCP ports using connect-only checks—no banner grabbing or port-range sweep.
- Inspects TLS metadata and makes bounded HTTP `HEAD`/`GET` requests.
- Records heuristic technology, PHP-version, and WAF/CDN signals visible in public responses.
- Optionally resolves wordlist-based subdomain candidates and checks a bounded set of URL paths. Both discovery modes are opt-in.
- Accepts an optional server-side PHP inventory CSV to improve assessment quality.
- Produces an Excel workbook with an executive dashboard, findings register, technical evidence, optional path discovery, remediation tracker, and methodology/references.

## What it deliberately does not do

- No exploit or proof-of-concept payloads for either CVE.
- No crafted multipart requests or upload-progress probes.
- No file uploads, command execution, authentication bypass, form submission, or destructive tests.
- No recursive crawling, credential collection, or use of supplied credentials.
- No attempt to declare a target safe based only on missing public PHP/WAF signals.

Path discovery does send one ordinary `GET` request per configured candidate path, so it creates additional traffic. Enable it only when approved and within the agreed testing window.

## Quick start

Requirements: Python 3.10 or newer.

```bash
git clone https://github.com/<YOUR-ORG>/php2shell-safe-exposure-scanner.git
cd php2shell-safe-exposure-scanner
python -m venv .venv
```

Activate the virtual environment, then install and run:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python php2shell_scan.py
```

The interactive mode asks how to supply targets, then asks which discovery profile to use. The choices are:

| Profile | Behavior |
|---|---|
| Standard | Scan only supplied targets; fastest and least traffic |
| DNS wordlist | Resolve candidate subdomains beneath approved root domains |
| Path wordlist | Request candidate URLs on supplied origins |
| Both | Enable DNS and path discovery |
| Custom | Select each discovery option separately |

Review the scope and any selected wordlists before confirming the scan.

## Examples

Scan a single authorized target:

```bash
python php2shell_scan.py --url https://portal.example.com --out reports/assessment.xlsx
```

Scan a list of approved targets:

```bash
python php2shell_scan.py --input targets.txt --out reports/assessment.xlsx
```

Scan targets with verified server-side inventory:

```bash
python php2shell_scan.py \
  --input targets.txt \
  --inventory php_inventory.csv \
  --out reports/assessment.xlsx
```

Enable DNS subdomain discovery (DNS lookups only for discovery candidates):

```bash
python php2shell_scan.py \
  --input targets.txt \
  --discover-subdomains \
  --wordlist subdomains_common.txt \
  --max-subdomains 500 \
  --workers 10 \
  --out reports/assessment.xlsx
```

Enable bounded URL path discovery:

```bash
python php2shell_scan.py \
  --input targets.txt \
  --discover-paths \
  --path-wordlist paths_common.txt \
  --max-paths 50 \
  --path-workers 5 \
  --path-delay 0.1 \
  --workers 10 \
  --out reports/assessment.xlsx
```

Show available options:

```bash
python php2shell_scan.py --help
```

### Target list format

`targets.txt` accepts one domain/URL per line, optional comments beginning with `#`, and simple comma-separated entries. Examples:

```text
# Replace these examples with approved assets before scanning
portal.example.com
https://app.example.org
http://legacy.example.net
```

Bare domains use HTTPS first and fall back to HTTP only when HTTPS does not establish a response. Explicit `http://` and `https://` schemes are respected. Duplicate normalized targets are removed. The bundled `targets.txt` is only a template; never commit real organizational scope unless it is intentionally public.

### Server-side PHP inventory

Use `php_inventory_template.csv` as the schema. Recommended columns:

`host,php_version,sapi,package_source,vendor_notes,asset_owner`

Use verified data from the origin server, image/build manifest, package manager, or hosting provider. In `vendor_notes`, include an advisory URL, package changelog, or change-ticket reference when documenting a backport. A free-text statement alone is not proof of remediation. Protect the inventory and generated report as internal security data.

## Scan behavior and limits

- Default TCP ports: `80,443,8080,8443,8000,8888,9443`.
- TCP checks are connect-only. `closed-or-filtered` means a connection was not established within the timeout; it does not distinguish a closed port from firewall filtering.
- Configured port checks are not a full `1–65535` scan.
- Default target concurrency is 20, configurable from 1 to 50. Use lower concurrency for sensitive/production systems or when required by the rules of engagement.
- Path discovery defaults to 100 candidates per origin and is capped at 2,000 per origin. A 100-target scope with 100 paths can generate approximately 10,000 candidate-path requests, in addition to baseline checks.
- Subdomain discovery defaults to a moderate wordlist and is capped at 5,000 candidates per root. Wildcard DNS detection suppresses automatic discovery for that root to reduce false positives.
- The scanner does not follow redirects for candidate-path requests. Status codes such as 200, 301, 401, and 403 are review leads, not confirmation of a vulnerable or sensitive endpoint.
- Response fingerprints may describe a CDN, reverse proxy, WAF, or application layer instead of the origin. Headers can be missing, inaccurate, or spoofed.
- The workbook does not intentionally include sampled HTML response bodies. It does include target URLs, hostnames, addresses, response metadata, and assessment notes; store it accordingly.

## Interpreting the report

The workbook distinguishes the baseline CVE severity from the per-target triage priority. A `P0` status means urgent verification or remediation based on available evidence; it is not proof of exploitation.

| Result type | Meaning |
|---|---|
| Public PHP version below the upstream fixed threshold | Low-confidence lead; verify the origin runtime and package |
| Server-side inventory reports an upstream affected version | Stronger version-based risk signal; verify exact package/build and vendor backport status |
| Reported version meets the upstream fixed threshold | Not enough on its own to prove the deployed package and workers are remediated |
| No PHP indicator found | Inconclusive; does not prove that PHP is absent or that the target is safe |
| WAF/CDN signature found | Indicates a visible signature only; does not prove effective mitigation or origin protection |
| No WAF/CDN signature found | Does not prove a WAF is absent |

For closure, verify the exact serving runtime and package/build, current PHP/vendor advisory, backport evidence (where applicable), deployment and worker restart/rollout, and asset-owner confirmation. PHP branch support lifecycle is separate from whether a particular fix is present.

## Current vulnerability references

Fixed upstream releases reported by the PHP security response for these CVEs include PHP **8.2.35**, **8.3.36**, **8.4.27**, and **8.5.12**. PHP 8.1 and older branches are upstream end-of-life; some vendors may provide backports, which must be verified against the exact package. These values can change as advisories are updated, so verify before making decisions.

- [PHP security archive](https://www.php.net/archive/2026.php)
- [PHP supported versions and lifecycle](https://www.php.net/supported-versions.php)
- [PHP advisory — CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory — CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [NCSC-NL PHP2Shell information repository](https://github.com/NCSC-NL/php2shell)

## Development and tests

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m py_compile php2shell_scan.py
```

The automated tests use local helper functions and temporary files; they do not scan public targets. GitHub Actions runs these checks for pull requests and pushes to the default branch.

## Data handling

Run locally on a trusted workstation or approved runner. The program does not upload scan results to a hosted service, but the destination workbook may contain sensitive infrastructure details. Review it before sharing or attaching it to public issues. Do not submit client or employer asset details, inventory CSVs, or scan reports in public GitHub issues.

## Contributing and security reports

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Use the issue templates for ordinary bugs and feature requests; privately disclose security defects rather than posting sensitive information publicly.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
