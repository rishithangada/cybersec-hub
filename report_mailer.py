#!/usr/bin/env python3
"""Create D2D Spirit report email drafts.

Hard rule: do not auto-send email. This module builds a Gmail-ready .eml draft
and saves the generated HTML report. A future explicit-send command can send a
saved draft after Rishi approves it.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import report_generator

ROOT = Path(__file__).resolve().parent
SENT_DIR = ROOT / "reports" / "sent"
FROM_EMAIL = "rishithang5@gmail.com"


def _safe_host(host: str) -> str:
  return re.sub(r"[^a-zA-Z0-9.-]+", "_", host or "unknown").strip("_") or "unknown"


def _severity_counts(findings: list[dict]) -> dict[str, int]:
  counts: dict[str, int] = {}
  for finding in findings:
    sev = str(finding.get("severity", "INFO")).upper()
    counts[sev] = counts.get(sev, 0) + 1
  return counts


def _summary_text(result: dict, client_name: str) -> str:
  findings = result.get("findings", []) or []
  counts = _severity_counts(findings)
  count_line = ", ".join(f"{sev}: {count}" for sev, count in sorted(counts.items())) or "No findings"
  top = findings[:3]
  top_lines = "\n".join(f"- [{f.get('severity','INFO')}] {f.get('issue','')}" for f in top) or "- None"
  return (
    f"Hi {client_name},\n\n"
    f"Your D2D Spirit security audit draft for {result.get('host', 'your domain')} is ready.\n\n"
    f"Severity counts: {count_line}\n\n"
    f"Top findings:\n{top_lines}\n\n"
    "This audit covers the scope defined in your authorization agreement. "
    "It is not a substitute for a comprehensive penetration test by a certified security firm.\n\n"
    "This message was generated as a draft and requires explicit approval before sending.\n"
  )


def send_report(result: dict, client_email: str, client_name: str) -> bool:
  """Generate and save a report email draft. Does not send automatically."""
  try:
    SENT_DIR.mkdir(parents=True, exist_ok=True)
    host = _safe_host(str(result.get("host", "unknown")))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    html = report_generator.generate(result)

    html_path = SENT_DIR / f"{host}_{stamp}_security_audit.html"
    html_path.write_text(html, encoding="utf-8")

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = client_email
    msg["Subject"] = f"Your D2D Spirit Security Report — {result.get('host', host)}"
    msg.set_content(_summary_text(result, client_name))
    msg.add_attachment(
      html.encode("utf-8"),
      maintype="text",
      subtype="html",
      filename=f"{host}_security_audit.html",
    )

    draft_path = SENT_DIR / f"{host}_{stamp}_draft.eml"
    draft_path.write_bytes(bytes(msg))
    return True
  except Exception as exc:
    print(f"report_mailer_failed: {exc}")
    return False


if __name__ == "__main__":
  sample = {
    "host": "example.com",
    "ip": "93.184.216.34",
    "scanned_at": datetime.now(timezone.utc).isoformat(),
    "open_ports": [],
    "ssl": None,
    "http_headers": None,
    "findings": [],
  }
  ok = send_report(sample, "client@example.com", "Client")
  print("draft_saved" if ok else "draft_failed")
