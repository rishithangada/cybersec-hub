#!/usr/bin/env python3
"""Passive self-audit for the D2D Spirit GitHub Pages site.

Hard scope:
- target is fixed to rishithangada.github.io/spirit-labs/
- one HTTPS page GET only
- no port scanning, no injection probes, no credential collection
"""

from __future__ import annotations

import html
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

TARGET_HOST = "rishithangada.github.io"
TARGET_PATH = "/spirit-labs/"
TARGET_LABEL = "rishithangada.github.io/spirit-labs"
TARGET_URL = f"https://{TARGET_HOST}{TARGET_PATH}"
REPORT_DIR = Path(__file__).resolve().parent / "reports" / "self-audit"
UA = "D2D-Spirit-Self-Audit/1.0"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class PageParser(HTMLParser):
  def __init__(self) -> None:
    super().__init__()
    self.inline_scripts = 0
    self.external_scripts: list[str] = []
    self.forms: list[str] = []
    self.meta_names: set[str] = set()
    self.has_charset = False

  def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
    attrs_d = {k.lower(): v or "" for k, v in attrs}
    if tag.lower() == "script":
      src = attrs_d.get("src", "").strip()
      if src:
        self.external_scripts.append(src)
      else:
        self.inline_scripts += 1
    elif tag.lower() == "form":
      self.forms.append(attrs_d.get("action", "").strip())
    elif tag.lower() == "meta":
      if "charset" in attrs_d:
        self.has_charset = True
      name = (attrs_d.get("name") or attrs_d.get("http-equiv") or "").strip().lower()
      if name:
        self.meta_names.add(name)


def now_iso() -> str:
  return datetime.now(timezone.utc).isoformat()


def add_check(
  checks: list[dict[str, Any]],
  category: str,
  name: str,
  result: str,
  detail: str,
  severity: str = "low",
) -> None:
  checks.append(
    {
      "category": category,
      "name": name,
      "result": result,
      "detail": detail,
      "severity": severity,
    }
  )


def one_get() -> tuple[int | None, dict[str, str], bytes, str | None]:
  req = urllib.request.Request(TARGET_URL, headers={"User-Agent": UA})
  try:
    with urllib.request.urlopen(req, timeout=10) as resp:
      return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(2_000_000), None
  except urllib.error.HTTPError as exc:
    return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read(2_000_000), None
  except Exception as exc:
    return None, {}, b"", str(exc)


def tls_info() -> dict[str, Any]:
  out: dict[str, Any] = {"valid": None}
  try:
    ctx = ssl.create_default_context()
    with socket.create_connection((TARGET_HOST, 443), timeout=8) as raw:
      with ctx.wrap_socket(raw, server_hostname=TARGET_HOST) as sock:
        cert = sock.getpeercert()
        out["valid"] = True
        out["tls_version"] = sock.version()
        out["cipher"] = sock.cipher()[0] if sock.cipher() else "unknown"

    expires_raw = cert.get("notAfter", "")
    expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    issuer = []
    for group in cert.get("issuer", ()):
      for key, value in group:
        if key in ("organizationName", "commonName"):
          issuer.append(value)
    out.update(
      {
        "expires": expires_raw,
        "days_until_expiry": (expires - datetime.now(timezone.utc)).days,
        "issuer": " / ".join(issuer) or "unknown",
      }
    )
  except ssl.SSLCertVerificationError as exc:
    out.update({"valid": False, "error": str(exc)})
  except Exception as exc:
    out.update({"valid": None, "error": str(exc)})
  return out


def dns_info() -> dict[str, Any]:
  out: dict[str, Any] = {"a": [], "cname": [], "spf": None, "dmarc": None, "dnssec": None}
  try:
    out["a"] = sorted({item[4][0] for item in socket.getaddrinfo(TARGET_HOST, 443, type=socket.SOCK_STREAM)})
  except Exception as exc:
    out["error"] = str(exc)

  try:
    canonical, aliases, ips = socket.gethostbyname_ex(TARGET_HOST)
    names = [canonical, *aliases]
    out["cname"] = [name for name in names if name and name != TARGET_HOST]
    if not out["a"] and ips:
      out["a"] = ips
  except Exception:
    pass

  try:
    import dns.resolver  # type: ignore

    def txt(name: str) -> list[str]:
      return ["".join(part.decode() for part in answer.strings) for answer in dns.resolver.resolve(name, "TXT")]

    out["spf"] = next((value for value in txt(TARGET_HOST) if value.lower().startswith("v=spf1")), "")
    out["dmarc"] = next((value for value in txt(f"_dmarc.{TARGET_HOST}") if value.lower().startswith("v=dmarc1")), "")
    try:
      out["dnssec"] = bool(list(dns.resolver.resolve(TARGET_HOST, "DNSKEY")))
    except Exception:
      out["dnssec"] = False
  except Exception:
    out["txt_skipped"] = "dnspython not installed; SPF, DMARC, and DNSSEC not checked"
  return out


def weak_cipher(cipher: str, tls_version: str) -> bool:
  value = f"{cipher} {tls_version}".upper()
  return any(token in value for token in ("RC4", "3DES", " DES", "MD5", "NULL", "TLSV1 ", "TLSV1.1"))


def header_checks(headers: dict[str, str], checks: list[dict[str, Any]]) -> None:
  required = [
    ("content-security-policy", "CSP", "High", "Missing CSP allows broader XSS impact."),
    ("x-frame-options", "X-Frame-Options", "High", "Missing clickjacking protection."),
    ("x-content-type-options", "X-Content-Type-Options", "Medium", "Missing nosniff header."),
    ("strict-transport-security", "HSTS", "Critical", "Missing HSTS; browsers may allow downgrade risk."),
    ("referrer-policy", "Referrer-Policy", "Medium", "Missing referrer privacy policy."),
    ("permissions-policy", "Permissions-Policy", "Medium", "Missing browser permissions restrictions."),
    ("x-xss-protection", "X-XSS-Protection", "Low", "Deprecated header not set; modern CSP is preferred."),
  ]
  for key, name, fail_sev, missing_detail in required:
    value = headers.get(key)
    if value:
      result = "PASS"
      detail = value
      severity = "low"
      if key == "x-xss-protection":
        result = "WARN"
        detail = f"{value} (deprecated header; do not rely on it)"
    else:
      result = "FAIL" if key in {"content-security-policy", "x-frame-options", "strict-transport-security"} else "WARN"
      detail = missing_detail
      severity = fail_sev.lower()
    add_check(checks, "headers", name, result, detail, severity)

  server = headers.get("server")
  if server:
    add_check(checks, "headers", "Server header", "WARN", f"Server fingerprint exposed: {server}", "low")
  else:
    add_check(checks, "headers", "Server header", "PASS", "No Server header exposed")


def ssl_checks(info: dict[str, Any], checks: list[dict[str, Any]]) -> None:
  if info.get("valid") is True:
    add_check(checks, "ssl", "Valid certificate", "PASS", "Certificate chain validates")
  elif info.get("valid") is False:
    add_check(checks, "ssl", "Valid certificate", "FAIL", info.get("error", "Certificate validation failed"), "critical")
  else:
    add_check(checks, "ssl", "Valid certificate", "FAIL", info.get("error", "TLS check failed"), "critical")

  days = info.get("days_until_expiry")
  if isinstance(days, int):
    result = "PASS" if days >= 30 else "WARN"
    add_check(checks, "ssl", "Certificate expiry", result, f"{days} days until expiry", "medium" if days < 30 else "low")
  else:
    add_check(checks, "ssl", "Certificate expiry", "WARN", "Expiry unavailable", "medium")

  add_check(checks, "ssl", "Issuer", "PASS" if info.get("issuer") else "WARN", str(info.get("issuer") or "Issuer unavailable"))

  version = str(info.get("tls_version") or "unknown")
  if version == "TLSv1.3":
    add_check(checks, "ssl", "TLS version", "PASS", "TLSv1.3 preferred")
  elif version == "TLSv1.2":
    add_check(checks, "ssl", "TLS version", "PASS", "TLSv1.2 minimum met")
  else:
    add_check(checks, "ssl", "TLS version", "FAIL", f"Weak or unknown TLS version: {version}", "critical")

  cipher = str(info.get("cipher") or "unknown")
  add_check(
    checks,
    "ssl",
    "Cipher suite",
    "WARN" if weak_cipher(cipher, version) else "PASS",
    cipher,
    "medium" if weak_cipher(cipher, version) else "low",
  )


def cookie_checks(headers: dict[str, str], checks: list[dict[str, Any]]) -> None:
  cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
  if not cookies:
    add_check(checks, "cookies", "Cookies", "PASS", "No cookies set")
    return
  joined = "\n".join(cookies).lower()
  add_check(checks, "cookies", "HttpOnly flag", "PASS" if "httponly" in joined else "WARN", "Checked Set-Cookie headers", "medium")
  add_check(checks, "cookies", "Secure flag", "PASS" if "secure" in joined else "WARN", "Checked Set-Cookie headers", "medium")
  add_check(checks, "cookies", "SameSite attribute", "PASS" if "samesite" in joined else "WARN", "Checked Set-Cookie headers", "medium")


def dns_checks(info: dict[str, Any], checks: list[dict[str, Any]]) -> None:
  if info.get("a"):
    add_check(checks, "dns", "A records", "PASS", ", ".join(info["a"]))
  else:
    add_check(checks, "dns", "A records", "FAIL", info.get("error", "No A records resolved"), "critical")

  cname = info.get("cname") or []
  add_check(checks, "dns", "CNAME records", "PASS" if cname else "WARN", ", ".join(cname) if cname else "No CNAME exposed via stdlib lookup")

  if info.get("spf") is None:
    add_check(checks, "dns", "SPF record", "WARN", info.get("txt_skipped", "SPF not checked"), "medium")
  else:
    add_check(checks, "dns", "SPF record", "PASS" if info.get("spf") else "WARN", info.get("spf") or "No SPF record found", "medium")

  if info.get("dmarc") is None:
    add_check(checks, "dns", "DMARC record", "WARN", info.get("txt_skipped", "DMARC not checked"), "medium")
  else:
    add_check(checks, "dns", "DMARC record", "PASS" if info.get("dmarc") else "WARN", info.get("dmarc") or "No DMARC record found", "medium")

  if info.get("dnssec") is None:
    add_check(checks, "dns", "DNSSEC", "WARN", info.get("txt_skipped", "DNSSEC not checked"), "low")
  else:
    add_check(checks, "dns", "DNSSEC", "PASS" if info.get("dnssec") else "WARN", "DNSKEY present" if info.get("dnssec") else "No DNSKEY record found", "low")


def content_checks(body: bytes, checks: list[dict[str, Any]]) -> dict[str, Any]:
  text = body.decode("utf-8", errors="replace")
  parser = PageParser()
  parser.feed(text)
  external = [urllib.parse.urljoin(TARGET_URL, src) for src in parser.external_scripts]
  unknown = [
    src for src in external
    if urllib.parse.urlparse(src).hostname not in {TARGET_HOST, "github.githubassets.com"}
  ]

  add_check(
    checks,
    "content",
    "Inline scripts",
    "WARN" if parser.inline_scripts else "PASS",
    f"{parser.inline_scripts} inline script block(s) detected" if parser.inline_scripts else "No inline scripts detected",
    "medium" if parser.inline_scripts else "low",
  )
  add_check(
    checks,
    "content",
    "External scripts",
    "WARN" if unknown else "PASS",
    ", ".join(unknown) if unknown else "No external scripts from unknown hosts",
    "medium" if unknown else "low",
  )

  insecure_forms = []
  for action in parser.forms:
    if not action:
      continue
    absolute = urllib.parse.urljoin(TARGET_URL, action)
    if urllib.parse.urlparse(absolute).scheme != "https":
      insecure_forms.append(action)
  if not parser.forms:
    add_check(checks, "content", "Forms", "PASS", "No forms present")
  else:
    add_check(
      checks,
      "content",
      "Forms",
      "FAIL" if insecure_forms else "PASS",
      f"Insecure form action(s): {', '.join(insecure_forms)}" if insecure_forms else "All form actions resolve to HTTPS or same-page HTTPS",
      "high" if insecure_forms else "low",
    )

  add_check(checks, "content", "Viewport meta", "PASS" if "viewport" in parser.meta_names else "WARN", "Viewport meta present" if "viewport" in parser.meta_names else "Viewport meta missing", "low")
  add_check(checks, "content", "Charset meta", "PASS" if parser.has_charset else "WARN", "Charset meta present" if parser.has_charset else "Charset meta missing", "low")

  return {
    "inline_scripts": parser.inline_scripts,
    "external_scripts": external,
    "forms": parser.forms,
    "has_viewport": "viewport" in parser.meta_names,
    "has_charset": parser.has_charset,
  }


def passive_owasp_checks(headers: dict[str, str], body: bytes, checks: list[dict[str, Any]]) -> None:
  server = headers.get("server", "")
  add_check(
    checks,
    "owasp",
    "A01 Broken Access Control",
    "WARN",
    "Directory listing probes skipped to honor single-GET passive-only rule",
    "low",
  )
  add_check(
    checks,
    "owasp",
    "A02 Cryptographic Failures",
    "WARN",
    "HTTP to HTTPS redirect check skipped to honor single-GET passive-only rule",
    "low",
  )
  add_check(
    checks,
    "owasp",
    "A05 Security Misconfiguration",
    "WARN" if server else "PASS",
    f"Server header exposed: {server}" if server else "No Server header exposed",
    "medium" if server else "low",
  )
  add_check(
    checks,
    "owasp",
    "A07 XSS reflected input",
    "WARN",
    "URL parameter reflection test skipped to honor single-GET passive-only rule",
    "low",
  )
  add_check(
    checks,
    "owasp",
    "A09 Logging / robots.txt",
    "WARN",
    "robots.txt check skipped to honor single-GET passive-only rule",
    "low",
  )


def score(checks: list[dict[str, Any]]) -> int:
  points = {"PASS": 2, "WARN": 1, "FAIL": 0}
  earned = sum(points.get(check["result"], 0) for check in checks)
  possible = len(checks) * 2
  return round((earned / possible) * 100) if possible else 0


def severity_counts(checks: list[dict[str, Any]]) -> dict[str, int]:
  counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
  for check in checks:
    if check["result"] == "PASS":
      continue
    sev = str(check.get("severity", "low")).lower()
    if sev in counts:
      counts[sev] += 1
  return counts


def build_report() -> dict[str, Any]:
  checks: list[dict[str, Any]] = []
  status, headers, body, error = one_get()
  if error:
    add_check(checks, "http", "Single HTTPS GET", "FAIL", error, "critical")
  else:
    add_check(checks, "http", "Single HTTPS GET", "PASS" if status and status < 400 else "WARN", f"HTTP status {status}")

  header_checks(headers, checks)
  ssl = tls_info()
  ssl_checks(ssl, checks)
  cookie_checks(headers, checks)
  dns = dns_info()
  dns_checks(dns, checks)
  content = content_checks(body, checks)
  passive_owasp_checks(headers, body, checks)

  counts = severity_counts(checks)
  report = {
    "target": TARGET_LABEL,
    "url": TARGET_URL,
    "scan_date": now_iso(),
    "score": score(checks),
    **counts,
    "checks": checks,
    "artifacts": {
      "http_status": status,
      "ssl": ssl,
      "dns": dns,
      "content": content,
    },
  }
  return report


def color(result: str) -> str:
  return {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED}.get(result, RESET)


def terminal(report: dict[str, Any]) -> str:
  lines = [
    f"{CYAN}{BOLD}D2D SPIRIT SELF-AUDIT{RESET}",
    f"Target: {report['url']}",
    f"Scan date: {report['scan_date']}",
    f"Score: {BOLD}{report['score']}/100{RESET}",
    f"Severity: critical={report['critical']} high={report['high']} medium={report['medium']} low={report['low']}",
    "",
  ]
  current = ""
  for check in report["checks"]:
    if check["category"] != current:
      current = check["category"]
      lines.append(f"{CYAN}## {current.upper()}{RESET}")
    result = check["result"]
    lines.append(f"  {color(result)}{result:<4}{RESET}  {check['name']}: {check['detail']}")
  return "\n".join(lines)


def esc(value: Any) -> str:
  return html.escape(str(value), quote=True)


def html_report(report: dict[str, Any]) -> str:
  rows = "\n".join(
    f"<tr><td>{esc(c['category'])}</td><td>{esc(c['name'])}</td>"
    f"<td><span class='badge {esc(c['result'].lower())}'>{esc(c['result'])}</span></td>"
    f"<td>{esc(c['severity'])}</td><td>{esc(c['detail'])}</td></tr>"
    for c in report["checks"]
  )
  return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>D2D Spirit Self-Audit — {esc(report['target'])}</title>
  <style>
    *{{box-sizing:border-box}} body{{margin:0;background:#050807;color:#d9ffe0;font-family:'Courier New',monospace}}
    body:before{{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(rgba(132,204,22,.04) 50%,transparent 50%);background-size:100% 4px;mix-blend-mode:screen}}
    .wrap{{max-width:1120px;margin:0 auto;padding:42px 22px 64px}}
    .terminal{{border:1px solid rgba(132,204,22,.35);background:linear-gradient(180deg,#07110b,#020403);box-shadow:0 0 38px rgba(132,204,22,.12);border-radius:10px;overflow:hidden}}
    .bar{{display:flex;gap:8px;align-items:center;border-bottom:1px solid rgba(132,204,22,.24);padding:12px 16px;color:#84cc16;background:#08140b}}
    .dot{{width:10px;height:10px;border-radius:50%;background:#84cc16;box-shadow:0 0 12px #84cc16}}
    .body{{padding:26px}} h1{{margin:0;color:#84cc16;font-size:24px;letter-spacing:2px}} .sub{{color:#8fd98f;margin-top:8px}}
    .score{{display:grid;grid-template-columns:180px 1fr;gap:22px;align-items:center;margin:26px 0;padding:18px;border:1px solid rgba(132,204,22,.24);background:#07110b}}
    .num{{font-size:54px;font-weight:900;color:#84cc16;text-shadow:0 0 22px rgba(132,204,22,.4)}} .sev{{display:flex;flex-wrap:wrap;gap:10px}}
    .pill{{border:1px solid rgba(255,255,255,.16);padding:7px 10px;border-radius:999px;color:#eaffea}}
    table{{width:100%;border-collapse:collapse;margin-top:20px}} th{{text-align:left;color:#84cc16;border-bottom:1px solid rgba(132,204,22,.35);padding:10px;font-size:12px;text-transform:uppercase;letter-spacing:1px}}
    td{{padding:11px 10px;border-bottom:1px solid rgba(132,204,22,.12);vertical-align:top;color:#d9ffe0}} .badge{{font-weight:900;border-radius:4px;padding:3px 8px;color:#020403}}
    .pass{{background:#22c55e}} .warn{{background:#facc15}} .fail{{background:#ef4444;color:white}} .footer{{margin-top:26px;color:#779b7b;font-size:12px;line-height:1.6}}
    @media(max-width:720px){{.score{{grid-template-columns:1fr}} .num{{font-size:42px}} td,th{{font-size:12px}}}}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="terminal">
      <div class="bar"><span class="dot"></span><strong>D2D SPIRIT // SELF-AUDIT REPORT</strong></div>
      <div class="body">
        <h1>DIRECT TO DEFEND</h1>
        <div class="sub">Target: {esc(report['url'])} · Scan: {esc(report['scan_date'])}</div>
        <div class="score">
          <div><div class="num">{esc(report['score'])}</div><div>/100 security score</div></div>
          <div class="sev">
            <span class="pill">Critical: {esc(report['critical'])}</span>
            <span class="pill">High: {esc(report['high'])}</span>
            <span class="pill">Medium: {esc(report['medium'])}</span>
            <span class="pill">Low: {esc(report['low'])}</span>
          </div>
        </div>
        <table>
          <thead><tr><th>Category</th><th>Check</th><th>Result</th><th>Severity</th><th>Detail</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        <div class="footer">
          Passive self-audit only: one HTTPS GET, DNS lookup, and TLS certificate inspection.
          This audit covers the scope defined in your authorization agreement. It is not a substitute for a comprehensive penetration test by a certified security firm.
        </div>
      </div>
    </section>
  </main>
</body>
</html>"""


def save(report: dict[str, Any]) -> tuple[Path, Path]:
  REPORT_DIR.mkdir(parents=True, exist_ok=True)
  stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
  json_path = REPORT_DIR / f"report_{stamp}.json"
  html_path = REPORT_DIR / f"report_{stamp}.html"
  json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
  html_path.write_text(html_report(report), encoding="utf-8")
  return json_path, html_path


def main() -> int:
  report = build_report()
  json_path, html_path = save(report)
  print(terminal(report))
  print()
  print(f"JSON saved: {json_path}")
  print(f"HTML saved: {html_path}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
