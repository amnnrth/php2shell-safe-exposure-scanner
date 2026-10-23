#!/usr/bin/env python3
"""
PHP2Shell Exposure Assessment (CVE-2026-109618 / CVE-2026-109619)

SAFE MODE BY DESIGN:
- Performs DNS lookup, TLS certificate inspection, HTTP HEAD/GET of the site root.
- Does NOT send exploit payloads, malformed multipart requests, upload-progress probes,
  or other requests intended to trigger the vulnerabilities.
- Public web fingerprinting cannot prove PHP runtime vulnerability. Use --inventory
  with trusted server-side version/package data for stronger assessment.

Examples:
  python php2shell_scan.py --url https://example.com
  python php2shell_scan.py --input targets.txt --out php2shell_report.xlsx
  python php2shell_scan.py --input targets.txt --inventory php_inventory.csv --out report.xlsx
  python php2shell_scan.py --input targets.txt --discover-paths --path-wordlist paths_common.txt --out report.xlsx
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import re
import socket
import secrets
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote

try:
    import requests
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.utils import get_column_letter
except ImportError as exc:
    print(f"Missing dependency: {exc}. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)

CVE_IDS = "CVE-2026-109618, CVE-2026-109619"
PATCHED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
USER_AGENT = "PHP2Shell-Safe-Exposure-Scanner/1.0.0 (non-exploit; authorized defensive scanning)"
TIMEOUT = 5
PORT_TIMEOUT = 0.8
DEFAULT_PORTS = "80,443,8080,8443,8000,8888,9443"
MAX_BODY = 150_000

def extract_target_value(value: str) -> str:
    """Accept bare domains, explicit URLs, and Markdown links copied from chat."""
    value = (value or "").strip().lstrip("\ufeff")
    if not value or value.startswith("#"):
        return ""
    # If copied from Markdown, prefer the actual link destination over the label.
    markdown = re.search(r"\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)", value, re.I)
    if markdown:
        return markdown.group(1).strip()
    # Also accept angle-bracket URL formatting.
    value = value.strip().strip("<>").strip()
    # Strip common trailing punctuation from pasted prose, without stripping URL path syntax.
    return value.rstrip(".,;")

def normalize_url(value: str) -> str:
    value = extract_target_value(value)
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    p = urlparse(value)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ValueError(f"Unsupported target URL: {value}")
    if p.username or p.password:
        raise ValueError("Do not put credentials in target URLs.")
    # Normalize scheme/host case, preserve explicit ports and paths, remove fragments.
    netloc = p.netloc.lower()
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", p.params, p.query, ""))

def load_targets(single: str | None, input_file: str | None, extra_values: list[str] | None = None) -> list[str]:
    values = []
    if single:
        values.append(single)
    if extra_values:
        values.extend(extra_values)
    if input_file:
        with open(input_file, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Support plain lines, Markdown links, and simple comma-separated lists.
                if re.search(r"\[[^\]]*\]\(\s*https?://", line, re.I):
                    values.append(line)
                else:
                    values.extend(part.strip() for part in line.split(",") if part.strip())
    out, seen = [], set()
    for v in values:
        u = normalize_url(v)
        if u and u not in seen:
            out.append(u)
            seen.add(u)
    if not out:
        raise ValueError("Provide --url or --input with at least one target.")
    return out

def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated TCP port list and validate the range."""
    ports = []
    for part in (value or DEFAULT_PORTS).split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port} (valid range: 1-65535)")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("Provide at least one TCP port to check.")
    if len(ports) > 64:
        raise ValueError("Limit the port list to 64 ports per target.")
    return ports

def check_tcp_ports(host: str, ports: list[int]) -> tuple[str, str]:
    """Concurrent, lightweight TCP connect checks only; no banner grabbing or exploitation."""
    def check_one(port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((host, port), timeout=min(PORT_TIMEOUT, TIMEOUT)):
                return port, True
        except (OSError, TimeoutError):
            return port, False
    # Bound per-host fan-out so large scans stay responsive without unbounded sockets.
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(ports)))) as pool:
        outcomes = list(pool.map(check_one, ports))
    opened = [port for port, is_open in outcomes if is_open]
    checked = [f"{port}/{'open' if is_open else 'closed-or-filtered'}" for port, is_open in outcomes]
    return ", ".join(map(str, opened)) or "None detected", "; ".join(checked)

def parse_php_version(value: str):
    if not value:
        return None
    m = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", value)
    return tuple(map(int, m.groups())) if m else None

def php_branch_lifecycle(version_text: str) -> str:
    """Lifecycle is a separate concern from whether the PHP2Shell fix is present."""
    v = parse_php_version(version_text or "")
    if not v:
        return "Not determined — verified PHP version required"
    major, minor, _ = v
    if major < 8 or (major == 8 and minor <= 1):
        return "EOL / unsupported upstream — verify vendor backport and plan upgrade"
    if (major, minor) == (8, 2):
        return "Security support ends 31 Dec 2026 — upgrade planning required"
    if (major, minor) == (8, 3):
        return "Security support currently available; ends 31 Dec 2027"
    if (major, minor) == (8, 4):
        return "Security support currently available; ends 31 Dec 2028"
    if (major, minor) == (8, 5):
        return "Supported branch; security support currently planned through 31 Dec 2029"
    return "Lifecycle not mapped — verify official PHP/vendor support policy"


def classify_version(version_text: str, vendor_notes: str = ""):
    """Return a cautious version assessment, triage priority, and action guidance."""
    v = parse_php_version(version_text or "")
    notes = (vendor_notes or "").lower()
    if not v:
        return ("PHP version not verified", "P0 - Urgent verification",
                "Obtain the installed runtime/package version from the origin host or hosting provider. Confirm vendor advisory and backport status before marking affected or fixed.")

    major, minor, patch = v
    fixed = PATCHED.get((major, minor)) if major == 8 else None
    vendor_fix_claim = any(x in notes for x in ("patched", "backport", "fixed by vendor", "not affected", "security update applied"))

    if fixed:
        if v < fixed:
            if vendor_fix_claim:
                return ("Below upstream fixed version — vendor backport claimed, not verified", "P0 - Urgent verification",
                        f"Reported version {version_text} is below upstream fixed version {'.'.join(map(str, fixed))}. Obtain vendor advisory/package changelog proving the backport; otherwise patch to {'.'.join(map(str, fixed))} or later in this branch.")
            return ("Affected by upstream version range — patch required", "P0 - Immediate remediation",
                    f"Reported version {version_text} is below upstream fixed version {'.'.join(map(str, fixed))}. Upgrade to {'.'.join(map(str, fixed))} or later in this branch, or verify a vendor backport with package evidence.")
        lifecycle = php_branch_lifecycle(version_text)
        if "ends 31 Dec 2026" in lifecycle:
            return ("Upstream PHP2Shell fix threshold met — branch nearing EOL", "P1 - Patch verified; plan upgrade",
                    f"Version {version_text} meets the upstream fixed threshold for these CVEs. Verify the installed package and runtime, then plan migration before PHP 8.2 security support ends on 31 Dec 2026.")
        return ("Upstream PHP2Shell fix threshold met — verify package provenance", "P2 - Validate and close",
                f"Version {version_text} meets the upstream fixed threshold. Confirm the actual serving runtime, package source, and vendor changelog before closing the finding.")

    if major < 8 or (major == 8 and minor <= 1):
        if vendor_fix_claim:
            return ("EOL branch — vendor backport claimed, not verified", "P0 - Urgent verification",
                    "PHP 8.1 and older are unsupported upstream. Obtain explicit vendor/package evidence that both CVEs are fixed, and plan migration to a supported branch. If no verifiable fix exists, isolate exposure and upgrade urgently.")
        return ("EOL branch — fix status unverified; treat as potentially affected", "P0 - Immediate remediation",
                "PHP 8.1 and older are unsupported upstream. Check for a vendor backport immediately; if no verifiable fix exists, upgrade to a supported fixed branch or apply a documented vendor-supported remediation. Consider temporary isolation for internet-facing systems.")

    if vendor_fix_claim:
        return ("Version outside current mapping — vendor fix claimed, verify advisory", "P1 - Vendor verification",
                "The version is not covered by this scanner's fixed-version mapping. Validate both CVEs against the official PHP/vendor advisory and package changelog; do not treat free-text notes alone as proof of remediation.")
    return ("Version outside current mapping — verify official advisory", "P1 - Vendor verification",
            "This version/branch is not covered by the scanner's fixed-version mapping. Verify the official PHP/vendor advisory, branch support status, and package changelog before determining affected status.")


def detect_technology_stack(headers: dict, body: str) -> tuple[str, str, str, str]:
    """Heuristic public fingerprinting. These values are leads, not authoritative inventory."""
    lower_body = (body or "").lower()
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    stack = []
    server_l = server.lower()
    powered_l = powered.lower()

    for needle, label in [("nginx", "nginx"), ("apache", "Apache HTTP Server"), ("openresty", "OpenResty"),
                          ("microsoft-iis", "Microsoft IIS"), ("cloudflare", "Cloudflare edge"),
                          ("litespeed", "LiteSpeed"), ("caddy", "Caddy"), ("envoy", "Envoy")]:
        if needle in server_l:
            stack.append("Web/edge: " + label)

    if "php" in powered_l or "php" in server_l or "phpsessid" in (headers.get("set-cookie", "").lower()):
        stack.append("Backend/runtime: PHP signal")
    for needle, label in [("wp-content", "WordPress"), ("wp-includes", "WordPress"),
                          ("drupal-settings-json", "Drupal"), ("/sites/default/", "Drupal"),
                          ("/media/system/js/", "Joomla"), ("content=\"joomla", "Joomla")]:
        if needle in lower_body:
            stack.append("CMS: " + label)
            break
    for needle, label in [("laravel", "Laravel"), ("livewire", "Laravel/Livewire"),
                          ("symfony", "Symfony"), ("__next", "Next.js"), ("_next/static", "Next.js"),
                          ("__nuxt", "Nuxt"), ("ng-version=", "Angular"), ("data-reactroot", "React"),
                          ("vite", "Vite asset tooling"), ("django", "Django"), ("flask", "Flask"),
                          ("asp.net", "ASP.NET")]:
        if needle in lower_body or needle in powered_l:
            item = "Framework/platform: " + label
            if item not in stack:
                stack.append(item)
    if "node.js" in powered_l or "express" in powered_l:
        stack.append("Backend/runtime: Node.js/Express signal")
    if "asp.net" in powered_l:
        stack.append("Backend/runtime: ASP.NET signal")

    php_version = ""
    php_source = ""
    for source_name, value in [("X-Powered-By", powered), ("Server", server)]:
        if re.search(r"php", value, re.I):
            version = parse_php_version(value)
            if version:
                php_version = ".".join(map(str, version))
                php_source = f"Public {source_name} header (unverified / spoofable)"
                break
    php_signal = bool("Backend/runtime: PHP signal" in stack or php_version)
    if php_version:
        confidence = "Low — version disclosed by public header only"
    elif php_signal or any(x in stack for x in ("CMS: WordPress", "CMS: Drupal", "CMS: Joomla", "Framework/platform: Laravel", "Framework/platform: Laravel/Livewire")):
        confidence = "Low-to-medium — heuristic public indicator; runtime not proven"
    elif stack:
        confidence = "Low — public fingerprint only; PHP not confirmed"
    else:
        confidence = "No reliable stack signal from sampled response"
    return "; ".join(dict.fromkeys(stack)) or "No stack fingerprint identified", php_version, php_source, confidence

def safe_dns(host: str):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        return ", ".join(ips), ""
    except Exception as e:
        return "", str(e)[:250]


def detect_waf(headers: dict, body: str = "") -> tuple[str, str]:
    """Detect public WAF/CDN hints only; absence of a signal does not mean no WAF."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    cookie = h.get("set-cookie", "")
    server = h.get("server", "")
    hints = []
    signatures = [
        ("cloudflare", lambda: "cloudflare" in server or "cf-ray" in h or "cf-cache-status" in h or "__cf_bm" in cookie or "cf_clearance" in cookie),
        ("Akamai", lambda: any(k.startswith("akamai-") for k in h) or "ak_bmsc" in cookie or "bm_sz" in cookie),
        ("Imperva / Incapsula", lambda: any(k.startswith("x-iinfo") for k in h) or "x-cdn" in h and "incapsula" in h.get("x-cdn", "") or "incap_ses" in cookie or "visid_incap" in cookie),
        ("Sucuri", lambda: "sucuri" in server or "x-sucuri-id" in h or "x-sucuri-cache" in h),
        ("AWS WAF / CloudFront possible", lambda: "cloudfront" in server or "x-amz-cf-id" in h or "x-amz-cf-pop" in h),
        ("Fastly edge possible", lambda: "fastly" in server or "x-served-by" in h and "cache-" in h.get("x-cache", "")),
        ("F5 / BIG-IP possible", lambda: "bigipserver" in cookie or "f5" in server),
        ("Generic WAF signal", lambda: any(k in h for k in ("x-waf", "x-firewall", "x-safedog"))),
    ]
    for label, predicate in signatures:
        try:
            if predicate(): hints.append(label)
        except Exception:
            pass
    if hints:
        return "Public WAF/CDN signal detected — not proof of protection", "; ".join(dict.fromkeys(hints))
    body_l = (body or "").lower()
    if any(x in body_l for x in ("attention required! | cloudflare", "request rejected", "web application firewall", "access denied - sucuri")):
        return "Possible WAF/challenge page", "Response body contains a common WAF/challenge phrase; verify manually"
    return "No public WAF signal observed — WAF absence not confirmed", "No recognizable response signature; check CDN/WAF configuration and owner inventory"


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return []
    words = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            word = line.strip().lower()
            if not word or word.startswith("#"):
                continue
            if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", word):
                words.append(word)
    return list(dict.fromkeys(words))


def discover_subdomains(root_domains: list[str], wordlist_path: str, workers: int = 20, limit: int = 1000) -> tuple[list[str], list[str]]:
    """Resolve only user-approved root-domain + wordlist combinations; no brute-force HTTP probing."""
    words = load_wordlist(wordlist_path)[:max(1, min(limit, 5000))]
    discovered, notes = [], []
    roots = []
    for value in root_domains:
        host = urlparse(normalize_url(value)).hostname or ""
        if host and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) and "." in host:
            roots.append(host.lower().strip("."))
    roots = list(dict.fromkeys(roots))
    if not roots or not words:
        return [], ["Subdomain discovery skipped: no valid root domains or usable wordlist entries."]
    for root in roots:
        # Wildcard DNS guard: a random label resolving indicates candidate results may be false positives.
        wildcard_host = f"wildcard-check-{secrets.token_hex(5)}.{root}"
        wildcard_ips, _ = safe_dns(wildcard_host)
        if wildcard_ips:
            notes.append(f"{root}: wildcard DNS detected; skipped automatic candidate discovery to avoid false positives. Review DNS manually or use a vetted non-wildcard method.")
            continue
        candidates = [f"{w}.{root}" for w in words]
        def resolves(host):
            ips, _ = safe_dns(host)
            return host if ips else ""
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 50))) as pool:
            for found in pool.map(resolves, candidates):
                if found:
                    discovered.append(found)
    return list(dict.fromkeys(discovered)), notes

def load_path_wordlist(path: str | None) -> list[str]:
    """Load safe relative URL paths. Full URLs, traversal, query strings, and fragments are rejected."""
    if not path:
        return []
    paths = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            value = value.strip("/").strip()
            if not value or "://" in value or "?" in value or "#" in value or "\\" in value or "%" in value:
                continue
            parts = value.split("/")
            if any(part in (".", "..") for part in parts):
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)*", value):
                continue
            paths.append(value)
    return list(dict.fromkeys(paths))


def _path_request(url: str, timeout: int) -> dict:
    """One bounded GET; do not follow redirects or store response bodies in the report."""
    try:
        with requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,text/plain,*/*"},
            timeout=max(3, min(int(timeout), 30)),
            allow_redirects=False,
            stream=True,
            verify=True,
        ) as response:
            try:
                raw = response.raw.read(8192, decode_content=True)
            except Exception:
                raw = b""
            encoding = response.encoding or "utf-8"
            body = raw.decode(encoding, errors="replace")[:8192]
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", title_match.group(1))).strip())[:180] if title_match else ""
            content_type = headers.get("content-type", "")[:160]
            try:
                content_length = int(headers.get("content-length", ""))
            except Exception:
                content_length = len(raw)
            # Keep redirects scoped in the report: strip query/fragment, never follow automatically.
            location = ""
            if headers.get("location"):
                try:
                    lp = urlparse(headers["location"])
                    location = urlunparse((lp.scheme, lp.netloc, lp.path, "", "", ""))[:300]
                except Exception:
                    location = "[unparsed redirect]"
            server = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            php_version, php_source = "", ""
            if "php" in (server + " " + powered).lower():
                v = parse_php_version(server + " " + powered)
                if v:
                    php_version = ".".join(map(str, v))
                    php_source = "Public response header on discovered path (unverified)"
            if not php_version:
                body_text = html.unescape(re.sub(r"<[^>]+>", " ", body))
                m = re.search(r"\bPHP\s+(?:Version\s*)?(\d+\.\d+\.\d+)\b", body_text, re.I)
                if m:
                    php_version = m.group(1)
                    php_source = "Response body resembles PHP version disclosure (unverified)"
            low_body = body.lower()
            phpinfo_like = (
                urlparse(url).path.lower().rstrip("/").endswith(("phpinfo.php", "info.php"))
                and ("php version" in low_body or "phpinfo()" in low_body or "php information" in low_body)
            ) or ("php version" in low_body and "configuration" in low_body and "phpinfo" in low_body)
            waf_status, waf_evidence = detect_waf(headers, body)
            stack, stack_version, stack_source, stack_conf = detect_technology_stack(headers, body)
            # Never store body content; just a short evidence note and signature hash for soft-404 comparison.
            normalized_body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip().lower()
            body_signature = hashlib.sha256(normalized_body[:1500].encode("utf-8", errors="ignore")).hexdigest() if normalized_body else ""
            return {
                "HTTP Status": response.status_code,
                "Page Title": title,
                "Content Type": content_type,
                "Content Length": content_length,
                "Redirect Location (query removed)": location,
                "Server Header": server[:200],
                "X-Powered-By": powered[:200],
                "WAF / CDN Signal": waf_status,
                "WAF Evidence": waf_evidence,
                "Detected Technology Stack": stack,
                "PHP Version Signal": php_version,
                "PHP Version Signal Source": php_source,
                "PHPInfo-like Page Signal": "Possible PHP information page — verify exposure" if phpinfo_like else "",
                "Response Confidence": "HTTP response received; route existence is heuristic",
                "HTTP Error": "",
                "_body_signature": body_signature,
                "_body_sample_len": len(raw),
            }
    except requests.RequestException as exc:
        return {
            "HTTP Status": "", "Page Title": "", "Content Type": "", "Content Length": "",
            "Redirect Location (query removed)": "", "Server Header": "", "X-Powered-By": "",
            "WAF / CDN Signal": "Not determined", "WAF Evidence": "No response available for signature check",
            "Detected Technology Stack": "No reliable stack signal", "PHP Version Signal": "",
            "PHP Version Signal Source": "", "PHPInfo-like Page Signal": "",
            "Response Confidence": "No HTTP response; this is not evidence the path is absent",
            "HTTP Error": str(exc)[:220], "_body_signature": "", "_body_sample_len": 0,
        }


def discover_url_paths(base_urls: list[str], wordlist_path: str, workers: int = 10,
                       limit: int = 100, timeout: int = 5, delay: float = 0.05) -> list[dict]:
    """Bounded URL/path wordlist check against supplied origins; GET only, no redirects or exploit probes."""
    paths = load_path_wordlist(wordlist_path)[:max(1, min(int(limit), 2000))]
    if not paths:
        return []
    bases = []
    for value in base_urls:
        try:
            p = urlparse(normalize_url(value))
            if p.scheme not in ("http", "https") or not p.hostname:
                continue
            origin = urlunparse((p.scheme, p.netloc, "/", "", "", ""))
            if origin not in bases:
                bases.append(origin)
        except Exception:
            continue
    results = []
    worker_count = max(1, min(int(workers), 25))
    timeout = max(3, min(int(timeout), 30))
    delay = max(0.0, min(float(delay), 1.0))
    total = len(bases) * len(paths)
    done = 0
    for base in bases:
        # One random non-existent path per origin helps identify generic soft-404/catch-all responses.
        baseline_path = f".__pathcheck_missing_{secrets.token_hex(8)}"
        baseline_url = base.rstrip("/") + "/" + baseline_path
        baseline = _path_request(baseline_url, timeout)
        base_host = urlparse(base).hostname or ""
        for chunk_start in range(0, len(paths), max(worker_count, worker_count * 4)):
            chunk = paths[chunk_start:chunk_start + max(worker_count, worker_count * 4)]
            def check_path(rel_path):
                url = base.rstrip("/") + "/" + quote(rel_path, safe="/._~-")
                row = _path_request(url, timeout)
                if delay:
                    time.sleep(delay)
                status = row.get("HTTP Status")
                baseline_status = baseline.get("HTTP Status")
                signature = row.pop("_body_signature", "")
                sample_len = row.pop("_body_sample_len", 0)
                base_signature = baseline.get("_body_signature", "")
                base_len = baseline.get("_body_sample_len", 0)
                title = row.get("Page Title", "")
                baseline_title = baseline.get("Page Title", "")
                same_title = bool(title and baseline_title and title.casefold() == baseline_title.casefold())
                similar_len = bool(sample_len and base_len and abs(sample_len - base_len) <= max(80, int(base_len * 0.12)))
                is_soft404 = bool(status and baseline_status == status and (
                    (signature and base_signature and signature == base_signature) or (same_title and similar_len)
                ))
                if is_soft404:
                    result_type = "Likely soft-404 / catch-all — manual review"
                    confidence = "Low — matches random missing-path response"
                elif status in (200, 201, 202, 204):
                    result_type = "HTTP success response — review path"
                    confidence = "Medium that endpoint responds; content/application meaning unverified"
                elif status in (301, 302, 303, 307, 308):
                    result_type = "Redirect response — review destination"
                    confidence = "Low-to-medium; redirect is not proof of exposure"
                elif status in (401, 403, 405):
                    result_type = "Protected / method / access response — review path"
                    confidence = "Low-to-medium; may be auth, ACL, or WAF behavior"
                elif status in (429, 500, 502, 503, 504):
                    result_type = "Rate-limit / server-error response — review manually"
                    confidence = "Low; transient, WAF, or backend behavior possible"
                elif status in (404, 410):
                    result_type = "Not found / gone response"
                    confidence = "Medium for status only; routing/catch-all can affect result"
                elif status:
                    result_type = "Other HTTP response — review manually"
                    confidence = "Low; HTTP status alone does not prove route existence"
                else:
                    result_type = "No HTTP response"
                    confidence = "None — connectivity failure is not a negative finding"
                if row.get("PHP Version Signal"):
                    row["PHP Version Signal Context"] = "Potentially useful for PHP2Shell triage; verify against server-side package/runtime inventory"
                else:
                    row["PHP Version Signal Context"] = "No PHP version signal in this limited response sample"
                return {
                    "Base URL": base,
                    "Hostname": base_host,
                    "Discovered URL": url,
                    "Wordlist Path": "/" + rel_path,
                    **row,
                    "Discovery Result": result_type,
                    "Assessment Confidence": confidence,
                    "_is_soft404": is_soft404,
                }
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                for r in pool.map(check_path, chunk):
                    done += 1
                    results.append(r)
        print(f"[PATH DISCOVERY] {base_host}: checked {len(paths)} paths ({done}/{total} total across origins).")
    return results


def tls_info(host: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                issuer = ", ".join(f"{k}={v}" for rdn in cert.get("issuer", []) for k, v in rdn)
                subject = ", ".join(f"{k}={v}" for rdn in cert.get("subject", []) for k, v in rdn)
                return {
                    "TLS Version": s.version() or "",
                    "TLS Cipher": (s.cipher() or ("",))[0],
                    "Certificate Subject": subject,
                    "Certificate Issuer": issuer,
                    "Certificate Not Before": cert.get("notBefore", ""),
                    "Certificate Not After": cert.get("notAfter", ""),
                    "TLS Error": "",
                }
    except Exception as e:
        return {
            "TLS Version": "", "TLS Cipher": "", "Certificate Subject": "",
            "Certificate Issuer": "", "Certificate Not Before": "", "Certificate Not After": "",
            "TLS Error": str(e)[:250],
        }

def fetch(url: str, method: str):
    try:
        r = requests.request(method, url, timeout=TIMEOUT, allow_redirects=True,
                             headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                             stream=(method == "GET"), verify=True)
        body = ""
        if method == "GET":
            chunks = []
            size = 0
            for chunk in r.iter_content(chunk_size=8192, decode_unicode=True):
                if not chunk:
                    continue
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8", "replace")
                chunks.append(chunk)
                size += len(chunk.encode("utf-8", "replace"))
                if size >= MAX_BODY:
                    break
            body = "".join(chunks)
        data = {
            "status": r.status_code,
            "final_url": r.url,
            "redirects": " -> ".join([x.url for x in r.history] + [r.url]),
            "headers": dict(r.headers),
            "body": body,
            "error": "",
        }
        r.close()
        return data
    except requests.RequestException as e:
        return {"status": "", "final_url": url, "redirects": "", "headers": {},
                "body": "", "error": str(e)[:300]}

def probe_open_web_services(host: str, opened_ports: list[int], primary_port: int) -> tuple[str, dict, str]:
    """Make one bounded, non-exploit GET request to open common web ports other than the primary URL port."""
    service_rows = []
    combined_headers = {}
    combined_body = []
    schemes = {80: "http", 443: "https", 8000: "http", 8080: "http", 8443: "https", 8888: "http", 9443: "https"}
    for port in opened_ports:
        if port == primary_port or port not in schemes:
            continue
        scheme = schemes[port]
        probe_url = f"{scheme}://{host}:{port}/"
        try:
            r = requests.get(probe_url, timeout=TIMEOUT, allow_redirects=False,
                             headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                             stream=True, verify=True)
            status_code = r.status_code
            hdrs = {str(k): str(v) for k, v in r.headers.items()}
            sample = []
            size = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8", "replace")
                sample.append(chunk)
                size += len(chunk.encode("utf-8", "replace"))
                if size >= 40_000:
                    break
            r.close()
            service_rows.append(f"{port}/{scheme}: HTTP {status_code}")
            for k, v in hdrs.items():
                # Keep the first useful value, but do not replace primary URL evidence.
                combined_headers.setdefault(k.lower(), v)
            if sample:
                combined_body.append(f"<!-- fingerprint source: {scheme} port {port} -->" + "".join(sample))
        except requests.RequestException as exc:
            service_rows.append(f"{port}/{scheme}: no HTTP response ({str(exc)[:100]})")
    return "; ".join(service_rows) or "No additional open web ports probed", combined_headers, "\n".join(combined_body)


def scan_target(url: str, delay: float = 0.05, ports: list[int] | None = None):
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    p = urlparse(url)
    host = p.hostname or ""
    dns, dns_error = safe_dns(host)
    ports_to_check = list(ports or parse_ports(DEFAULT_PORTS))
    # Explicit non-standard target ports are always checked even if omitted from --ports.
    if p.port and p.port not in ports_to_check:
        ports_to_check.append(p.port)
    port_summary, port_details = check_tcp_ports(host, ports_to_check)
    tls = tls_info(host, p.port or 443) if p.scheme == "https" else {
        "TLS Version": "", "TLS Cipher": "", "Certificate Subject": "",
        "Certificate Issuer": "", "Certificate Not Before": "", "Certificate Not After": "",
        "TLS Error": "Target URL uses HTTP; TLS was not tested."
    }
    head = fetch(url, "HEAD")
    time.sleep(max(0, delay))
    get = fetch(url, "GET")
    active_url = url
    fallback_note = ""
    # HTTPS first for hostname-only targets; fall back to HTTP only if HTTPS cannot
    # establish a response at all (not merely because the server returns 4xx/5xx).
    if p.scheme == "https" and head.get("error") and get.get("error"):
        http_url = urlunparse(("http", p.netloc, p.path or "/", p.params, p.query, ""))
        http_head = fetch(http_url, "HEAD")
        time.sleep(max(0, delay))
        http_get = fetch(http_url, "GET")
        if not http_head.get("error") or not http_get.get("error"):
            head, get, active_url = http_head, http_get, http_url
            fallback_note = "HTTPS failed to establish a response; HTTP fallback used."
    primary_port = p.port or (443 if p.scheme == "https" else 80)
    opened_numbers = []
    try:
        opened_numbers = [int(x.strip()) for x in port_summary.split(",") if x.strip().isdigit()]
    except Exception:
        opened_numbers = []
    extra_services, extra_headers, extra_body = probe_open_web_services(host, opened_numbers, primary_port)
    headers = {k.lower(): str(v) for k, v in {**head.get("headers", {}), **get.get("headers", {})}.items()}
    # Include additional open web-port fingerprints, while preserving primary response headers.
    for k, v in extra_headers.items():
        headers.setdefault(k.lower(), str(v))
    body = (get.get("body", "") or "") + "\n" + extra_body
    evidence = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    set_cookie = headers.get("set-cookie", "")
    if fallback_note: evidence.append(fallback_note)
    if server: evidence.append(f"Server header: {server}")
    if powered: evidence.append(f"X-Powered-By: {powered}")
    if "PHPSESSID" in set_cookie: evidence.append("PHPSESSID cookie observed")
    if re.search(r"php(?:/|\s|[-.]?\d)", server + " " + powered, re.I):
        evidence.append("PHP-related product/version string in response headers")
    if "PHPSESSID" in body: evidence.append("PHPSESSID string in HTML body")
    if re.search(r"\.php(?:[?#\"' /]|$)", body, re.I): evidence.append("PHP endpoint references found in sampled HTML")
    if re.search(r"wp-content|wp-includes", body, re.I): evidence.append("WordPress markers found in sampled HTML")
    if re.search(r"drupal-settings-json|/sites/default/", body, re.I): evidence.append("Drupal markers found in sampled HTML")
    if re.search(r"joomla|/media/system/js/", body, re.I): evidence.append("Possible Joomla markers found in sampled HTML")
    tech_stack, public_php_version, public_php_source, fingerprint_confidence = detect_technology_stack(headers, body)
    waf_status, waf_evidence = detect_waf(headers, body)
    php_likely_tech = any(marker in tech_stack for marker in ("CMS: WordPress", "CMS: Drupal", "CMS: Joomla", "Framework/platform: Laravel"))
    php_signal = bool(public_php_version or "PHP signal" in tech_stack or "PHPSESSID" in set_cookie or php_likely_tech or
                      re.search(r"php(?:/|\s|[-.]?\d)", server + " " + powered, re.I))
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else ""
    status = get.get("status", "")
    if get.get("error"):
        verdict = "Assessment incomplete — HTTP request failed"
        severity = "P1 - Validate connectivity and inventory"
        confidence = "None — no reliable HTTP response"
        rationale = "No reliable HTTP response was obtained. This is not a clean bill of health; validate DNS, TLS, WAF/allowlisting, and the origin runtime using server-side inventory."
        next_action = "Retry from an approved network path; ask the asset owner/hosting provider for PHP runtime, package source, SAPI, and patch evidence."
    elif php_signal:
        if public_php_version:
            v_status, severity, guidance = classify_version(public_php_version)
            verdict = "Public PHP version signal — not authoritative"
            confidence = "Low — version is disclosed by a public header and may be spoofed or differ from origin runtime"
            rationale = f"A public response disclosed PHP {public_php_version}. Version-based triage suggests: {v_status}. Verify the actual origin runtime/package and any vendor backport before confirming impact."
            next_action = guidance
        else:
            verdict = "Potential PHP exposure — server-side version unverified"
            severity = "P0 - Urgent verification"
            confidence = fingerprint_confidence
            rationale = "PHP-related public indicators were observed, but no trustworthy runtime version is available. The CVEs are critical; urgently verify the origin runtime and package patch status. This is a verification priority, not a confirmed vulnerability."
            next_action = "Urgently obtain the origin PHP version, SAPI/handler, package source, vendor backport status, and application owner; patch if below the fixed threshold."
    else:
        verdict = "PHP not identified — backend remains unconfirmed"
        severity = "P1 - Inventory validation"
        confidence = fingerprint_confidence
        rationale = "No strong PHP indicator was observed in the sampled root response. CDNs, reverse proxies, hidden routes, serverless backends, and products embedding PHP can mask the runtime. Do not mark not affected from this result alone."
        next_action = "Check CMDB/cloud/container/hosting inventory for PHP-based applications and embedded runtimes; confirm with the application owner."
    return {
        "Scan Time UTC": started, "Target URL": url, "Hostname": host, "Target Discovery Source": "Supplied target list",
        "Resolved IPs": dns, "DNS Error": dns_error,
        "TCP Ports Open": port_summary, "TCP Port Check Details": port_details,
        "Additional Web Services": extra_services,
        "HTTP Status": status, "Final URL": get.get("final_url", url),
        "Redirect Chain": get.get("redirects", ""), "Page Title": title,
        "Server Header": server, "X-Powered-By": powered,
        "Set-Cookie (redacted)": re.sub(r"(?i)(PHPSESSID=)[^;,\s]+", r"\1[REDACTED]", set_cookie)[:500],
        "PHP2Shell Assessment": verdict, "Severity / Priority": severity,
        "CVE Severity (baseline)": "Critical — CVSS v4.0 9.2 (vendor advisory)",
        "Assessment Confidence": confidence,
        "Detected Technology Stack": tech_stack,
        "WAF / CDN Signal": waf_status,
        "WAF Evidence": waf_evidence,
        "PHP2Shell Impact Status": "INCONCLUSIVE — server-side PHP runtime/package not verified",
        "Public PHP Version": public_php_version,
        "Public PHP Version Source": public_php_source,
        "Assessment Rationale": rationale, "Recommended Next Action": next_action,
        "Public Indicators": "; ".join(evidence) or "No PHP-specific indicator found in sampled response",
        "HTTP Error": (get.get("error") or head.get("error", "")) + ((" | " + fallback_note) if fallback_note else ""),
        **tls,
        "CVE IDs": CVE_IDS,
    }

def load_inventory(path: str | None):
    """CSV columns: host,php_version,sapi,package_source,vendor_notes,asset_owner"""
    inv = {}
    if not path:
        return inv
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            host = (row.get("host") or "").strip().lower()
            if host:
                inv[host] = row
    return inv

def apply_inventory(result, inventory):
    row = inventory.get(result["Hostname"].lower())
    public_version = result.get("Public PHP Version", "")
    if not row:
        result["Server-Side PHP Version"] = ""
        result["PHP SAPI / Handler"] = ""
        result["Package Source"] = ""
        result["Asset Owner"] = ""
        result["Vendor Notes / Evidence"] = ""
        result["PHP Branch Lifecycle"] = php_branch_lifecycle(public_version) if public_version else "Not determined — server-side version required"
        result["Version-Based Assessment"] = ("Public header version only — verify server-side" if public_version else "Not verified — obtain server-side PHP inventory")
        if public_version:
            status, priority, guidance = classify_version(public_version)
            result["Version-Based Assessment"] = f"Public-only estimate: {status}"
            result["Severity / Priority"] = priority
            result["Recommended Next Action"] = "Treat public version as a lead only. " + guidance
        result["Remediation Guidance"] = result.get("Recommended Next Action", "Identify the origin PHP runtime/package, SAPI/handler, package source, vendor patch/backport status, and asset owner. Do not classify as not affected based on absent public indicators.")
        if public_version:
            parsed = parse_php_version(public_version)
            fixed = PATCHED.get((parsed[0], parsed[1])) if parsed and parsed[0] == 8 else None
            if parsed and fixed and parsed < fixed:
                impact = "POTENTIALLY AFFECTED — public version is below upstream fix threshold; confirm origin"
            elif parsed and (parsed[0] < 8 or (parsed[0] == 8 and parsed[1] <= 1)):
                impact = "EOL / UNSUPPORTED PUBLIC VERSION SIGNAL — potentially affected; vendor backport must be evidenced"
            elif parsed and fixed and parsed >= fixed:
                impact = "VERSION HINT ONLY — public version appears at/above upstream threshold; verify origin package"
            else:
                impact = "VERSION HINT ONLY — branch not mapped; verify official advisory and origin package"
            result["PHP2Shell Impact Status"] = impact
        else:
            result["PHP2Shell Impact Status"] = "INCONCLUSIVE — public response cannot confirm backend PHP/version"
        return

    ver = (row.get("php_version") or "").strip()
    notes = (row.get("vendor_notes") or "").strip()
    status, priority, guidance = classify_version(ver, notes)
    result["Server-Side PHP Version"] = ver
    result["PHP SAPI / Handler"] = (row.get("sapi") or "").strip()
    result["Package Source"] = (row.get("package_source") or "").strip()
    result["Asset Owner"] = (row.get("asset_owner") or "").strip()
    result["Vendor Notes / Evidence"] = notes
    result["PHP Branch Lifecycle"] = php_branch_lifecycle(ver)
    parsed = parse_php_version(ver)
    fixed = PATCHED.get((parsed[0], parsed[1])) if parsed and parsed[0] == 8 else None
    has_evidence_ref = bool(re.search(r"https?://|\b(?:CHG|INC|SEC|CVE|GHSA|RHSA|USN|DSA|ALSA)[-:# ]?[A-Za-z0-9._/-]+\b", notes, re.I))
    explicit_not_affected = bool(re.search(r"\bnot affected\b|\bremediated\b|\bpatched\b|\bfixed\b|\bbackport applied\b", notes, re.I))
    if explicit_not_affected and has_evidence_ref:
        impact = "OWNER/VENDOR-REPORTED NOT AFFECTED OR REMEDIATED — evidence reference supplied; reviewer validation required"
    elif explicit_not_affected:
        impact = "REMEDIATION CLAIM — evidence reference missing; do not close yet"
    elif ver and fixed and parsed < fixed:
        impact = "LIKELY AFFECTED — inventory version below upstream fix threshold; verify vendor backport"
    elif ver and fixed and parsed >= fixed:
        impact = "UPSTREAM FIX THRESHOLD MET — confirm installed package, serving runtime, and restart/rollout"
    elif ver and (parsed and (parsed[0] < 8 or (parsed[0] == 8 and parsed[1] <= 1))):
        impact = "HIGH RISK / EOL — backport status must be evidenced; upgrade strongly recommended"
    else:
        impact = "INCONCLUSIVE — verify official advisory, package source, and runtime"
    result["PHP2Shell Impact Status"] = impact
    result["Version-Based Assessment"] = status
    result["Severity / Priority"] = priority
    result["Remediation Guidance"] = guidance
    result["Recommended Next Action"] = guidance
    if ver:
        result["PHP2Shell Assessment"] = "Inventory-based version assessment — stronger evidence; verify package/runtime"
        result["Assessment Confidence"] = "Medium — supplied server-side inventory; high only after package evidence and runtime confirmation"
        result["Assessment Rationale"] = f"Server-side inventory reports PHP {ver}. {status}. Validate the package actually serving this hostname, vendor backports, and restart/rollout completion."
    else:
        result["PHP2Shell Assessment"] = "Inventory provided, but PHP version missing"
        result["PHP2Shell Impact Status"] = "INCONCLUSIVE — inventory row has no PHP version"
        result["Assessment Confidence"] = "Low — inventory row lacks version"
        result["Severity / Priority"] = "P0 - Urgent verification"
        result["Recommended Next Action"] = "Complete the inventory with installed PHP version, SAPI/handler, package source, vendor advisory/backport evidence, and asset owner."
        result["Remediation Guidance"] = result["Recommended Next Action"]

def style_sheet(ws, freeze="A2"):
    ws.freeze_panes = freeze
    ws.auto_filter.ref = ws.dimensions
    for cell in ws[1]:
        cell.fill = PatternFill("solid", fgColor="17365D")
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 32
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            cell.border = Border(bottom=Side(style="hair", color="D9E2F3"))
    for col in ws.columns:
        letter = get_column_letter(col[0].column)
        max_len = max((len(str(c.value or "")) for c in col[:100]), default=10)
        ws.column_dimensions[letter].width = min(max(max_len + 2, 14), 52)

def excel_safe(value):
    """Prevent untrusted response text from being interpreted as an Excel formula."""
    if isinstance(value, str):
        # Spreadsheet applications may evaluate cells beginning with these markers.
        stripped = value.lstrip(" \t\r\n")
        if stripped.startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def create_report(results, out_path, started, duration, inventory_path=None, path_results=None, path_discovery_enabled=False):
    """Create a polished executive XLSX with dashboard, findings, evidence, actions, and methodology."""
    from openpyxl.chart import BarChart, DoughnutChart, Reference
    from openpyxl.chart.label import DataLabelList

    wb = Workbook()
    navy, blue, teal = "15324F", "1F5E8C", "00A6A6"
    pale, white, red, orange, yellow, green = "EEF3F8", "FFFFFF", "C00000", "ED7D31", "FFC000", "70AD47"

    def title_band(ws, cell_range, title):
        ws.merge_cells(cell_range)
        c = ws[cell_range.split(":")[0]]
        c.value = title
        c.fill = PatternFill("solid", fgColor=navy)
        c.font = Font(name="Aptos Display", size=19, bold=True, color=white)
        c.alignment = Alignment(vertical="center")
        ws.row_dimensions[c.row].height = 38

    def table_header(ws, row=1):
        for c in ws[row]:
            c.fill = PatternFill("solid", fgColor=blue)
            c.font = Font(name="Aptos", bold=True, color=white)
            c.alignment = Alignment(vertical="center", wrap_text=True)
        ws.row_dimensions[row].height = 34

    def polish_table(ws, freeze="A2"):
        ws.freeze_panes = freeze
        if ws.max_row > 1:
            ws.auto_filter.ref = ws.dimensions
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.alignment = Alignment(vertical="top", wrap_text=True)
                c.border = Border(bottom=Side(style="hair", color="D7E0EA"))
                if c.row % 2 == 0 and c.fill.fill_type is None:
                    c.fill = PatternFill("solid", fgColor="F7F9FC")
        for col in ws.columns:
            letter = get_column_letter(col[0].column)
            max_len = max((len(str(c.value or "")) for c in col[:120]), default=12)
            ws.column_dimensions[letter].width = min(max(max_len + 2, 13), 48)

    path_results = path_results or []
    assessment_counts, severity_counts = {}, {}
    for r in results:
        a = r.get("PHP2Shell Assessment", "Not assessed")
        assessment_counts[a] = assessment_counts.get(a, 0) + 1
        sev = r.get("Severity / Priority", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    n = len(results)
    php_signals = sum(bool(r.get("Public PHP Version") or "PHP signal" in r.get("Detected Technology Stack", "") or "PHP" in r.get("Public Indicators", "")) for r in results)
    potentially_vulnerable = sum(("Affected by upstream" in r.get("Version-Based Assessment", "") or "EOL branch" in r.get("Version-Based Assessment", "")) for r in results)
    fixed_indicators = sum("threshold met" in r.get("Version-Based Assessment", "").lower() for r in results)
    no_inventory = sum(not r.get("Server-Side PHP Version") for r in results)
    urgent = sum(str(r.get("Severity / Priority", "")).startswith("P0") for r in results)
    eol = sum(("EOL / unsupported" in r.get("PHP Branch Lifecycle", "") or "ends 31 Dec 2026" in r.get("PHP Branch Lifecycle", "")) for r in results)
    waf_signals = sum("signal detected" in r.get("WAF / CDN Signal", "").lower() or "possible waf" in r.get("WAF / CDN Signal", "").lower() for r in results)
    path_candidates = sum(not r.get("_is_soft404") and r.get("Discovery Result", "") not in ("Not found / gone response", "No HTTP response") for r in path_results)
    path_php_signals = sum(bool(r.get("PHP Version Signal")) for r in path_results)

    # Dashboard
    dash = wb.active
    dash.title = "Executive Dashboard"
    dash.sheet_view.showGridLines = False
    title_band(dash, "A1:H1", "PHP2SHELL | EXPOSURE ASSESSMENT")
    dash.merge_cells("A2:H2")
    dash["A2"] = f"CONFIDENTIAL • Generated {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')} • {CVE_IDS}"
    dash["A2"].font = Font(italic=True, color="5B6573", size=10)
    dash.merge_cells("A3:H3")
    dash["A3"] = f"Scan duration: {duration:.1f}s  |  Inventory-assisted assessment: {'Yes' if inventory_path else 'No'}  |  Mode: Non-exploit external triage"
    dash["A3"].font = Font(color="5B6573", size=10)
    cards = [
        ("A5:B5","A6:B7","TARGETS ASSESSED",n,blue),
        ("C5:D5","C6:D7","PUBLIC PHP SIGNALS",php_signals,orange),
        ("E5:F5","E6:F7","VERSION-BASED AFFECTED / EOL",potentially_vulnerable,red),
        ("G5:H5","G6:H7","FIX THRESHOLD MET",fixed_indicators,green),
    ]
    for tr, vr, label, value, color in cards:
        dash.merge_cells(tr); dash.merge_cells(vr)
        t, v = dash[tr.split(":")[0]], dash[vr.split(":")[0]]
        t.value, v.value = label, value
        t.fill = PatternFill("solid", fgColor=color); t.font = Font(bold=True, color=white, size=10)
        t.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        v.fill = PatternFill("solid", fgColor=pale); v.font = Font(bold=True, color=color, size=26)
        v.alignment = Alignment(horizontal="center", vertical="center")
    dash.row_dimensions[5].height = 27
    dash.row_dimensions[6].height = 30
    dash.row_dimensions[7].height = 30

    dash.merge_cells("A9:D9"); dash["A9"] = "ASSESSMENT DISTRIBUTION"
    dash.merge_cells("E9:H9"); dash["E9"] = "SEVERITY / PRIORITY SNAPSHOT"
    for cell in (dash["A9"], dash["E9"]):
        cell.fill = PatternFill("solid", fgColor=blue); cell.font = Font(bold=True, color=white)
    dash["A11"], dash["B11"] = "Public-response assessment", "Targets"
    for c in dash[11][:2]: c.font = Font(bold=True, color=navy)
    items = sorted(assessment_counts.items(), key=lambda x: (-x[1], x[0])) or [("No targets scanned",0)]
    for i,(label,count) in enumerate(items, start=12):
        dash.cell(i,1,label); dash.cell(i,2,count)
    dash["E11"], dash["F11"] = "Severity / Priority", "Targets"
    for c in dash[11][4:6]: c.font = Font(bold=True, color=navy)
    sev_order = ["P0 - Immediate remediation", "P0 - Urgent verification", "P1 - Validate connectivity and inventory", "P1 - Inventory validation", "P1 - Vendor verification", "P1 - Patch verified; plan upgrade", "P2 - Validate and close"]
    for i,sev in enumerate(sev_order,start=12):
        dash.cell(i,5,sev); dash.cell(i,6,severity_counts.get(sev,0))
    bar = BarChart()
    bar.type = "bar"; bar.style = 10; bar.title = "Assessment results"
    bar.y_axis.title = "Assessment"; bar.x_axis.title = "Target count"
    bar.height = 7.2; bar.width = 14
    bar.add_data(Reference(dash,min_col=2,min_row=11,max_row=11+len(items)),titles_from_data=True)
    bar.set_categories(Reference(dash,min_col=1,min_row=12,max_row=11+len(items)))
    bar.legend = None
    dash.add_chart(bar,"A20")
    donut = DoughnutChart()
    donut.title = "Severity distribution"; donut.style = 10; donut.holeSize = 55
    donut.height = 7.2; donut.width = 11
    donut.add_data(Reference(dash,min_col=6,min_row=11,max_row=11+len(sev_order)),titles_from_data=True)
    donut.set_categories(Reference(dash,min_col=5,min_row=12,max_row=11+len(sev_order)))
    donut.dataLabels = DataLabelList(); donut.dataLabels.showPercent = True
    dash.add_chart(donut,"E20")

    note_row = max(37, 22+len(items))
    dash.merge_cells(start_row=note_row,start_column=1,end_row=note_row,end_column=8)
    dash.cell(note_row,1,"EXECUTIVE INTERPRETATION & PRIORITY ACTIONS")
    dash.cell(note_row,1).fill = PatternFill("solid",fgColor=blue)
    dash.cell(note_row,1).font = Font(bold=True,color=white)
    notes = [
        ("Assessment boundary","Non-exploit external triage only: DNS, TLS, HTTP HEAD/GET, response headers, and limited HTML sampling."),
        ("Critical caveat","Public PHP indicators do not prove a vulnerable runtime. No PHP indicator does not prove a system is safe."),
        ("Prioritize",f"{urgent} target(s) require urgent verification/remediation based on the available signals. These are triage decisions, not proof of successful exploitation."),
        ("Version-based risk",f"{potentially_vulnerable} target(s) have an inventory/public-version estimate in an affected upstream range or an EOL branch. Public headers alone are low-confidence evidence."),
        ("Lifecycle risk / EOL approaching",f"{eol} target(s) have a reported PHP 8.1-or-older EOL branch or PHP 8.2 security support ending 31 Dec 2026."),
        ("Coverage gap",f"{no_inventory} target(s) have no server-side PHP version in the inventory. Confirm origin runtime, SAPI/handler, package provenance, and owner."),
        ("Impact status interpretation","LIKELY AFFECTED is version-based triage, not exploit confirmation. UPSTREAM FIX THRESHOLD MET is not proof of deployed remediation. NOT AFFECTED requires evidence tied to the exact serving package/runtime."),
        ("WAF/CDN visibility",f"{waf_signals} target(s) showed a public WAF/CDN signature. This is not proof of effective protection; no signal does not prove absence. WAF does not replace patching."),
        ("URL path discovery", (f"Enabled: checked {len(path_results)} wordlist paths across supplied origins; {path_candidates} response(s) warrant review and {path_php_signals} PHP version signal(s) were observed. These are route-discovery leads, not vulnerability confirmations." if path_discovery_enabled else "Not run. Enable URL path discovery for a bounded wordlist check such as /phpinfo.php, /login, /admin, /api, and /health. Use only approved origins.")),
        ("Patch validation","Verify the current official PHP/vendor advisory, backports, and installed package changelog before closure."),
        ("Operational note","Only scan authorized assets. Treat hostnames, IPs, headers, and asset ownership as internal security data."),
    ]
    for i,(label,value) in enumerate(notes,start=note_row+1):
        dash.cell(i,1,label).font = Font(bold=True,color=navy)
        dash.merge_cells(start_row=i,start_column=2,end_row=i,end_column=8)
        dash.cell(i,2,value).alignment = Alignment(wrap_text=True,vertical="top")
        dash.row_dimensions[i].height = 34 if len(value)>115 else 25
    for col in "ABCDEFGH": dash.column_dimensions[col].width = 18
    dash.column_dimensions["A"].width = 28; dash.column_dimensions["E"].width = 25
    dash.freeze_panes = "A5"
    dash.sheet_properties.pageSetUpPr.fitToPage = True
    dash.page_setup.orientation = "landscape"; dash.page_setup.fitToWidth = 1; dash.page_setup.fitToHeight = 1

    # Findings register
    findings = wb.create_sheet("Findings Register")
    fields = ["Scan Time UTC","Target URL","Hostname","Target Discovery Source","Resolved IPs","TCP Ports Open","TCP Port Check Details","HTTP Status","Final URL",
        "PHP2Shell Assessment","CVE Severity (baseline)","Severity / Priority","Assessment Confidence","Assessment Rationale",
        "Detected Technology Stack","WAF / CDN Signal","WAF Evidence","PHP2Shell Impact Status","Public PHP Version","Public PHP Version Source","Additional Web Services","Public Indicators",
        "Server-Side PHP Version","PHP SAPI / Handler","PHP Branch Lifecycle","Version-Based Assessment","Remediation Guidance","Recommended Next Action",
        "Package Source","Asset Owner","Vendor Notes / Evidence","Server Header","X-Powered-By","Set-Cookie (redacted)",
        "TLS Version","TLS Cipher","Certificate Subject","Certificate Issuer","Certificate Not Before",
        "Certificate Not After","TLS Error","DNS Error","HTTP Error","Redirect Chain","Page Title","CVE IDs"]
    findings.append(fields)
    for r in results: findings.append([excel_safe(r.get(k, "")) for k in fields])
    table_header(findings); polish_table(findings)
    priority_col = fields.index("Severity / Priority") + 1
    for row in range(2,findings.max_row+1):
        sev=str(findings.cell(row,priority_col).value or "")
        color=red if sev.startswith("P0 - Immediate") else orange if sev.startswith(("P0", "P1")) else yellow if sev.startswith("P2") else pale
        findings.cell(row,priority_col).fill=PatternFill("solid",fgColor=color)
        findings.cell(row,priority_col).font=Font(bold=True,color=white if color in (red,orange) else "17202A")

    # Technical evidence
    tech = wb.create_sheet("Technical Evidence")
    tech_fields = ["Target URL","Hostname","Resolved IPs","DNS Error","TCP Ports Open","TCP Port Check Details","HTTP Status","Final URL","Redirect Chain","Page Title",
        "Detected Technology Stack","WAF / CDN Signal","WAF Evidence","PHP2Shell Impact Status","Public PHP Version","Public PHP Version Source","Additional Web Services","Assessment Confidence","Server Header","X-Powered-By","Set-Cookie (redacted)","Public Indicators","TLS Version","TLS Cipher",
        "Certificate Subject","Certificate Issuer","Certificate Not Before","Certificate Not After","TLS Error","HTTP Error","CVE IDs"]
    tech.append(tech_fields)
    for r in results: tech.append([excel_safe(r.get(k, "")) for k in tech_fields])
    table_header(tech); polish_table(tech)

    # URL path discovery (optional; separate from the PHP2Shell vulnerability verdict)
    path_ws = wb.create_sheet("URL Path Discovery")
    path_fields = ["Base URL", "Hostname", "Discovered URL", "Wordlist Path", "HTTP Status", "Discovery Result",
        "Assessment Confidence", "Page Title", "Content Type", "Content Length", "Redirect Location (query removed)",
        "Detected Technology Stack", "WAF / CDN Signal", "WAF Evidence", "PHP Version Signal", "PHP Version Signal Source",
        "PHPInfo-like Page Signal", "PHP Version Signal Context", "Server Header", "X-Powered-By", "HTTP Error", "Response Confidence"]
    path_ws.append(path_fields)
    for item in path_results:
        path_ws.append([excel_safe(item.get(k, "")) for k in path_fields])
    if not path_results:
        path_ws.append(["", "", "", "", "", "URL path wordlist discovery was enabled but produced no path records." if path_discovery_enabled else "URL path discovery not enabled. Re-run with --discover-paths or enable it in the interactive menu."] + [""] * (len(path_fields) - 6))
    table_header(path_ws); polish_table(path_ws)
    # Keep URL and evidence columns comfortably readable without oversized worksheet width.
    for col, width in {"A": 28, "B": 24, "C": 58, "D": 28, "F": 43, "G": 45, "H": 32, "L": 42, "M": 45, "N": 50, "O": 18, "P": 48, "Q": 45, "R": 62, "U": 42, "V": 54}.items():
        path_ws.column_dimensions[col].width = width
    path_ws.freeze_panes = "A2"

    # Action tracker
    rem = wb.create_sheet("Remediation Tracker")
    plan = [
        ["Priority","Action","Suggested Owner","Evidence / Completion Criteria","Status","Target Date","Notes"],
        ["P0 - Immediate","Confirm the actual origin PHP runtime/version for every internet-facing PHP app, including CDN/WAF origins and embedded runtimes.","Infrastructure / Application Owners","Hostname mapped to origin/runtime, PHP SAPI/handler, exact package version/source, environment, and named owner.","Open","",""],
        ["P0 - Immediate","Patch versions below the fixed upstream release or obtain verifiable vendor backport evidence.","Infrastructure / Application Owners","Package manager/build artifact evidence confirms fix; PHP-FPM/Apache/LiteSpeed workers restarted or containers rolled out; smoke tests passed.","Open","",""],
        ["P0 - Immediate","For PHP 8.1 and older, verify vendor backports urgently and plan migration to a supported branch; contain if no fix can be verified.","Infrastructure / Application Owners","Vendor advisory/package changelog or approved isolation/upgrade record; unsupported branch risk accepted only through formal exception.","Open","",""],
        ["P1 - High","For PHP 8.2, schedule migration before upstream security support ends on 31 Dec 2026.","Application Owner / Platform Engineering","Upgrade plan, tested target branch, change ticket, and agreed deadline.","Open","",""],
        ["P1 - High","Review web/PHP logs, EDR telemetry, unexpected child processes, file changes, and suspicious outbound connections.","SOC / Detection Engineering","Investigation documented; suspicious activity triaged; incident response opened if warranted.","Open","",""],
        ["P1 - High","Review WAF/CDN logs for unusual multipart POST patterns and upload-progress indicators; do not rely on WAF instead of patching.","SOC / Network Security","Logs reviewed; detections validated; patch status independently confirmed.","Open","",""],
        ["P1 - High","Repeat safe external checks after remediation and validate using authenticated/server-side package evidence.","Security Engineering","Evidence attached and finding status updated with reviewer and date.","Open","",""],
        ["P2 - Follow-up","Add PHP runtime version, package source, and ownership to asset inventory and patch governance.","Security Governance / IT Operations","Recurring review and unsupported-runtime alerting established.","Open","",""],
    ]
    for row in plan: rem.append(row)
    table_header(rem); polish_table(rem)
    for row in rem.iter_rows(min_row=2): row[1].font = Font(bold=True,color=navy)

    # Methodology
    method = wb.create_sheet("Methodology & References")
    rows = [
        ["Item","Description"],
        ["Purpose",f"Authorized defensive triage for {CVE_IDS}. Verify CVE identifiers and fixed versions against current official advisories before use."],
        ["Checks performed","DNS resolution, optional DNS-only subdomain wordlist discovery, optional bounded URL path wordlist checks (one GET per candidate, no redirect following, random missing-path baseline, soft-404 heuristic), TCP connect checks for configured ports, TLS metadata, HTTP HEAD/GET, limited body sampling, public technology/PHP indicators, and heuristic WAF/CDN signatures."],
        ["WAF detection caveat","WAF/CDN results are heuristic public-response signals only. No signature is not proof of absence; presence is not proof that the origin is protected or the CVEs are mitigated."],
        ["Subdomain discovery caveat","Subdomain wordlist discovery resolves candidate names only, is opt-in, and should be used only for approved root domains. Wildcard DNS is detected and causes automatic candidate scanning to be skipped to reduce false positives."],
        ["URL path discovery caveat","When enabled, checks relative paths from paths_common.txt using one bounded GET request per candidate, does not follow redirects, and does not send exploit payloads. Soft-404/catch-all matching is heuristic. 200/401/403 responses are leads only and can reflect SPA routing, auth, ACL, or WAF behavior. Response bodies are not written to the workbook."],
        ["Impact status semantics","LIKELY AFFECTED means version-range risk, not confirmed exploitation. UPSTREAM FIX THRESHOLD MET means the reported version meets the upstream threshold but package provenance/runtime/rollout still require validation. NOT AFFECTED requires exact asset/package evidence and reviewer sign-off."],
        ["Not performed","No crafted multipart probes, exploit payloads, file uploads, authentication bypass, command execution, denial-of-service testing, or destructive requests."],
        ["Public-response limitation","Public technology stack and PHP version detection are heuristics. Headers can be spoofed, hidden, or reflect a proxy rather than the origin. A negative result is not proof of non-impact."],
        ["Inventory-assisted assessment","Server-side inventory is stronger evidence, but confirm the exact package/build, serving runtime, vendor backports, and restart/rollout state."],
        ["Triage priority P0","Use for an upstream affected version, EOL branch with no verified backport, or PHP signal without a verified runtime version. This is remediation urgency, not proof of exploitation."],
        ["Triage priority P1","Use for failed/incomplete checks, unverified branch/vendor packages, or cases requiring vendor confirmation."],
        ["Triage priority P1 / P2","Use P1 when public checks are inconclusive or no PHP signal was observed without server-side inventory. Use P2 only when the upstream fix threshold appears met and package/runtime verification remains. Never infer not-affected from no public signal."],
        ["Version and lifecycle separation","A version may meet the PHP2Shell fix threshold but still be EOL or nearing EOL. Track CVE patch status and branch support as separate fields."],
        ["Configured fixed thresholds","PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 8.1 and older are EOL upstream; vendors may provide backports. PHP 8.2 security support ends 31 Dec 2026. Verify current official advisories."],
        ["Official PHP security advisory","https://www.php.net/archive/2026.php"],
        ["PHP supported versions / lifecycle","https://www.php.net/supported-versions.php"],
        ["GitHub advisory — CVE-2026-109618","https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"],
        ["GitHub advisory — CVE-2026-109619","https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"],
        ["Reference — NCSC-NL software inventory","https://github.com/NCSC-NL/php2shell"],
        ["Safety note","The referenced active scanner may send crafted probes. This workbook's scanner intentionally does not reproduce those probes."],
    ]
    for row in rows: method.append(row)
    table_header(method); polish_table(method)
    method.column_dimensions["A"].width=30; method.column_dimensions["B"].width=110
    for i in range(2,method.max_row+1): method.row_dimensions[i].height=38 if len(str(method.cell(i,2).value or ""))>120 else 26

    wb.properties.title = "PHP2Shell Exposure Assessment"
    wb.properties.subject = CVE_IDS
    wb.properties.creator = "Security Engineering"
    wb.properties.description = "Executive dashboard, findings register, technical evidence, optional URL path discovery, remediation tracker, and methodology."
    wb.active = 0
    Path(out_path).parent.mkdir(parents=True,exist_ok=True)
    wb.save(out_path)

def interactive_wizard():
    print("\n" + "=" * 62)
    print(" PHP2SHELL EXPOSURE SCANNER | INTERACTIVE MODE")
    print(" HTTPS first, HTTP fallback if HTTPS cannot connect")
    print("=" * 62)
    print("Choose how to provide authorized target domains:")
    print("  [1] Single domain")
    print("  [2] Bulk — enter/paste multiple domains")
    print("  [3] Bulk — load domains from a .txt file")
    print("  [4] Bulk — text file + server-side PHP inventory CSV")
    print("  [5] Exit")
    while True:
        choice = input("\nSelect option [1-5]: ").strip()
        if choice in {"1","2","3","4","5"}:
            break
        print("Please enter 1, 2, 3, 4, or 5.")
    if choice == "5":
        print("Cancelled.")
        raise SystemExit(0)

    single, input_file, inventory_file, extra_values = None, None, None, []
    if choice == "1":
        single = input("Enter domain (e.g. example.com): ").strip()
        if not single:
            print("No domain entered. Cancelled.")
            raise SystemExit(1)
    elif choice == "2":
        print("Paste one domain/URL per line: company.com, http://company2.com, or https://company3.com.")
        print("Markdown links copied from chat are accepted too, e.g. [https://example.com](https://example.com).")
        print("Bare domains try HTTPS first, then HTTP if HTTPS cannot connect; explicit schemes are respected.")
        print("Submit a blank line when finished.")
        while True:
            line = input("Domain: ").strip()
            if not line:
                if extra_values:
                    break
                print("Enter at least one domain.")
                continue
            if not line.startswith("#"):
                extra_values.append(line)
    else:
        input_file = input("Path to domain list .txt file [targets.txt]: ").strip() or "targets.txt"
        if choice == "4":
            inventory_file = input("Path to PHP inventory CSV [php_inventory_template.csv]: ").strip() or "php_inventory_template.csv"

    print("\nChoose discovery profile:")
    print("  [1] Standard scan — supplied domains only (fastest)")
    print("  [2] DNS wordlist — discover subdomains, then scan them")
    print("  [3] Path wordlist — check common URLs on supplied domains")
    print("  [4] Both — DNS subdomains + URL paths (broader coverage)")
    print("  [5] Custom — choose each discovery option separately")
    while True:
        profile = input("Select profile [1-5, default 1]: ").strip() or "1"
        if profile in {"1", "2", "3", "4", "5"}:
            break
        print("Please enter 1, 2, 3, 4, or 5.")
    discover = profile in {"2", "4"}
    discover_paths = profile in {"3", "4"}
    if profile == "5":
        discover = input("Enable DNS subdomain wordlist discovery? [y/N]: ").strip().lower() in ("y", "yes")
        discover_paths = input("Enable URL path wordlist discovery? [y/N]: ").strip().lower() in ("y", "yes")
    wordlist_file = None
    if discover:
        wordlist_file = input("Subdomain wordlist path [subdomains_common.txt]: ").strip() or "subdomains_common.txt"
    path_wordlist_file = None
    max_paths = 100
    path_workers = 10
    path_delay = 0.05
    if discover_paths:
        path_wordlist_file = input("URL path wordlist path [paths_common.txt]: ").strip() or "paths_common.txt"
        max_paths = input("Maximum paths per origin (1-2000) [100]: ").strip() or "100"
        path_workers = input("Concurrent URL path checks (1-25) [10]: ").strip() or "10"
        path_delay = input("Delay after each URL path request in seconds [0.05]: ").strip() or "0.05"
    out_file = input("Excel report filename [php2shell_report.xlsx]: ").strip() or "php2shell_report.xlsx"
    timeout = input("Request timeout in seconds [10]: ").strip() or "10"
    workers = input("Parallel targets (1-50) [20]: ").strip() or "20"
    ports_text = input(f"TCP ports to check [{DEFAULT_PORTS}]: ").strip() or DEFAULT_PORTS
    delay = input("Delay between HEAD and GET in seconds [0.05]: ").strip() or "0.05"
    try:
        timeout = max(3,min(int(timeout),30))
        workers = max(1,min(int(workers),50))
        ports = parse_ports(ports_text)
        delay = max(0.0,min(float(delay),2.0))
        targets = load_targets(single,input_file,extra_values)
        inventory = load_inventory(inventory_file)
        if discover and not Path(wordlist_file).exists():
            raise FileNotFoundError(f"Subdomain wordlist not found: {wordlist_file}")
        max_paths = max(1, min(int(max_paths), 2000))
        path_workers = max(1, min(int(path_workers), 25))
        path_delay = max(0.0, min(float(path_delay), 1.0))
        if discover_paths and not Path(path_wordlist_file).exists():
            raise FileNotFoundError(f"URL path wordlist not found: {path_wordlist_file}")
    except Exception as e:
        print(f"Input error: {e}")
        raise SystemExit(2)
    print("\n" + "-" * 62)
    print(f"Targets loaded : {len(targets)}")
    print(f"Subdomain discovery: {'Enabled (' + str(wordlist_file) + ')' if discover else 'Disabled'}")
    print(f"URL path discovery : {'Enabled (' + str(path_wordlist_file) + f', max {max_paths}/origin)' if discover_paths else 'Disabled'}")
    print(f"Inventory CSV  : {inventory_file or 'Not supplied (public-only triage)'}")
    print(f"Output workbook: {Path(out_file).resolve()}")
    print(f"Timeout/workers: {timeout}s / {workers}")
    print(f"TCP ports       : {','.join(map(str, ports))} (connect-only checks)")
    print("Protocol policy: HTTPS first; HTTP fallback only if HTTPS has no response")
    print("Request policy : DNS/TLS + HTTP HEAD/GET; no exploit probes")
    print("-" * 62)
    confirm = input("Start scan? [Y/n]: ").strip().lower()
    if confirm not in ("", "y", "yes"):
        print("Cancelled.")
        raise SystemExit(0)
    return single, input_file, inventory_file, out_file, timeout, workers, delay, extra_values, ports, discover, wordlist_file, discover_paths, path_wordlist_file, max_paths, path_workers, path_delay

def main():
    global TIMEOUT
    ap = argparse.ArgumentParser(description="Safe PHP2Shell exposure triage scanner (non-exploit).")
    ap.add_argument("--interactive", action="store_true", help="Launch interactive menu.")
    ap.add_argument("--url", help="Single domain or URL.")
    ap.add_argument("--input", help="Text file containing one authorized domain/URL per line.")
    ap.add_argument("--inventory", help="Optional CSV with server-side PHP inventory.")
    ap.add_argument("--out", default="php2shell_report.xlsx", help="Output XLSX path.")
    ap.add_argument("--workers", type=int, default=20, help="Concurrent targets (1-50; start at 20).")
    ap.add_argument("--ports", default=DEFAULT_PORTS, help=f"Comma-separated TCP ports to check (default: {DEFAULT_PORTS}).")
    ap.add_argument("--discover-subdomains", action="store_true", help="Opt-in DNS-only wordlist discovery beneath supplied root domains.")
    ap.add_argument("--wordlist", default="subdomains_common.txt", help="Wordlist file used with --discover-subdomains.")
    ap.add_argument("--max-subdomains", type=int, default=1000, help="Maximum wordlist entries per root domain (1-5000).")
    ap.add_argument("--discover-paths", action="store_true", help="Opt-in bounded HTTP path/endpoint wordlist checks on supplied origins.")
    ap.add_argument("--path-wordlist", default="paths_common.txt", help="Relative URL path wordlist used with --discover-paths.")
    ap.add_argument("--max-paths", type=int, default=100, help="Maximum URL paths per origin (1-2000).")
    ap.add_argument("--path-workers", type=int, default=10, help="Concurrent path checks (1-25).")
    ap.add_argument("--path-delay", type=float, default=0.05, help="Delay after each path request in seconds (0-1).")
    ap.add_argument("--delay", type=float, default=0.05, help="Delay between HEAD and GET per target.")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="HTTP/TLS timeout in seconds (3-30).")
    args = ap.parse_args()

    if args.interactive or (not args.url and not args.input):
        single, input_file, inventory_file, out_file, timeout, workers, delay, extra_values, ports, discover, wordlist_file, discover_paths, path_wordlist_file, max_paths, path_workers, path_delay = interactive_wizard()
        args.url, args.input, args.inventory, args.out = single, input_file, inventory_file, out_file
        args.timeout, args.workers, args.delay, args.ports = timeout, workers, delay, ",".join(map(str, ports))
        args.discover_subdomains = discover
        if wordlist_file: args.wordlist = wordlist_file
        args.discover_paths = discover_paths
        if path_wordlist_file: args.path_wordlist = path_wordlist_file
        args.max_paths, args.path_workers, args.path_delay = max_paths, path_workers, path_delay
    else:
        if args.url and args.input:
            ap.error("Use either --url or --input, not both.")
        inventory_file, out_file = args.inventory, args.out
        extra_values = []
    TIMEOUT = max(3,min(args.timeout,30))
    workers = max(1,min(args.workers,50))
    try:
        ports = parse_ports(args.ports)
        targets = load_targets(args.url,args.input,extra_values)
        inventory = load_inventory(inventory_file)
        if args.discover_subdomains:
            root_domains = [urlparse(u).hostname or "" for u in targets]
            found, discovery_notes = discover_subdomains(root_domains, args.wordlist, workers, max(1, min(args.max_subdomains, 5000)))
            base_targets = {urlparse(u).hostname for u in targets}
            for host in found:
                if host not in base_targets:
                    targets.append("https://" + host + "/")
            print(f"Subdomain DNS discovery: {len(found)} candidate(s) resolved; {len(targets)} total target(s) queued.")
            for note in discovery_notes: print("[DISCOVERY NOTE] " + note)
    except Exception as e:
        ap.error(str(e))
    if not args.discover_subdomains:
        found = []
    if args.max_paths < 1 or args.max_paths > 2000:
        ap.error("--max-paths must be between 1 and 2000.")
    if args.path_workers < 1 or args.path_workers > 25:
        ap.error("--path-workers must be between 1 and 25.")
    if args.discover_paths and not Path(args.path_wordlist).exists():
        ap.error(f"URL path wordlist not found: {args.path_wordlist}")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.time()
    results = []
    discovered_hosts = set(found) if args.discover_subdomains else set()
    print(f"\nPHP2Shell safe exposure scan | {len(targets)} target(s) | {CVE_IDS}")
    print("HTTPS first; HTTP fallback only if HTTPS cannot establish a response.")
    print(f"TCP ports: {','.join(map(str, ports))} (connect-only); HTTP checks use supplied URL/default web ports.")
    print("Checks: DNS/TLS + HTTP HEAD/GET. No exploit payloads or active vulnerability probes.")
    if args.discover_subdomains: print(f"Wordlist: {args.wordlist} | max entries/root: {max(1,min(args.max_subdomains,5000))} | DNS-only discovery")
    total = len(targets)
    # Bound queued work so very large input lists do not create one Future per target.
    batch_size = max(workers, workers * 4)
    completed = 0
    for batch_start in range(0, total, batch_size):
        batch = targets[batch_start:batch_start + batch_size]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scan_target,u,args.delay,ports):u for u in batch}
            for future in as_completed(futures):
                url = futures[future]
                completed += 1
                try:
                    r = future.result()
                    apply_inventory(r,inventory)
                    if r.get("Hostname") in discovered_hosts:
                        r["Target Discovery Source"] = "Wordlist DNS discovery"
                    results.append(r)
                    print(f"[{completed}/{total}] {r['Severity / Priority']:<13} ports={r.get('TCP Ports Open','')} | {url}")
                except Exception as e:
                    print(f"[{completed}/{total}] [ERROR] {url}: {e}",file=sys.stderr)
    order = {u:i for i,u in enumerate(targets)}
    results.sort(key=lambda r:order.get(r["Target URL"],999999))
    path_results = []
    if args.discover_paths:
        # Use the requested hostname only; if HTTPS fell back to HTTP on that same host, respect it.
        base_urls = []
        for r in results:
            original = urlparse(r.get("Target URL", ""))
            candidate = urlparse(r.get("Final URL", ""))
            if candidate.scheme in ("http", "https") and candidate.hostname and candidate.hostname.lower() == (original.hostname or "").lower():
                base_urls.append(urlunparse((candidate.scheme, candidate.netloc, "/", "", "", "")))
            elif original.scheme in ("http", "https") and original.hostname:
                base_urls.append(urlunparse((original.scheme, original.netloc, "/", "", "", "")))
        base_urls = list(dict.fromkeys(base_urls))
        print(f"\nURL path discovery: {len(base_urls)} supplied origins | {args.path_wordlist} | max {args.max_paths}/origin | workers={args.path_workers} | delay={args.path_delay}s")
        path_results = discover_url_paths(base_urls, args.path_wordlist, args.path_workers, args.max_paths, TIMEOUT, args.path_delay)
        print(f"URL path discovery complete: {len(path_results)} candidate path requests recorded.")
    create_report(results,out_file,started,time.time()-t0,inventory_file,path_results,args.discover_paths)
    print(f"\nElite Excel report saved: {Path(out_file).resolve()}")
    print("Sheets: Executive Dashboard | Findings Register | Technical Evidence | URL Path Discovery | Remediation Tracker | Methodology & References")
    print("Stack/version fingerprints are heuristic. Verify the origin runtime and vendor backports before declaring affected or fixed.")

if __name__ == "__main__":
    main()
