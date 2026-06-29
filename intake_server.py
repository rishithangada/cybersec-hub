#!/usr/bin/env python3
"""D2D Spirit client intake and authorization-gated scan server.

Runs on port 5001. Uses Flask when installed; otherwise serves the same v1 JSON
endpoints with stdlib http.server so local development still starts cleanly.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports"
EMAIL_RE = re.compile(r"^[^\s@]{1,120}@[^\s@]{1,255}\.[^\s@]{2,}$")

import auth_gate
import report_generator
import report_mailer
import scanner

try:
  from flask import Flask, jsonify, request
except Exception:
  Flask = None
  jsonify = None
  request = None


def _json(data: dict, status: int = 200):
  if jsonify is not None:
    return jsonify(data), status
  return status, json.dumps(data).encode("utf-8")


def _client_ip(headers: dict[str, str], remote_addr: str | None) -> str:
  forwarded = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or ""
  return (forwarded.split(",", 1)[0].strip() or remote_addr or "")


def _validate_intake(data: dict) -> tuple[str, int] | None:
  if not data.get("owns_confirmed"):
    return "Client must confirm they own or are authorized to test this domain.", 403
  if not data.get("roe_confirmed"):
    return "Client must explicitly authorize D2D Spirit to perform security testing.", 403
  if not auth_gate.normalize_domain(str(data.get("domain", ""))):
    return "Domain is required.", 400
  if not str(data.get("client_name", "")).strip():
    return "Client name is required.", 400
  if not EMAIL_RE.match(str(data.get("client_email", "")).strip()):
    return "Valid client email is required.", 400
  return None


def create_intake(data: dict, headers: dict[str, str], remote_addr: str | None):
  err = _validate_intake(data)
  if err:
    msg, status = err
    return {"error": msg}, status
  intake_id = auth_gate.create_authorization(
    str(data["domain"]),
    str(data["client_name"]),
    str(data["client_email"]),
    owns_confirmed=bool(data["owns_confirmed"]),
    roe_confirmed=bool(data["roe_confirmed"]),
    ip=_client_ip(headers, remote_addr),
  )
  return {
    "intake_id": intake_id,
    "status": "authorized",
    "message": "Authorization recorded. Passive scan is available; active audit requires payment confirmation.",
  }, 200


def passive_scan(intake_id: str):
  auth = auth_gate.get_authorization(intake_id)
  if not auth or not auth["owns_domain_confirmed"] or not auth["roe_confirmed"]:
    return {"error": "No valid authorization for this intake_id."}, 403
  result = scanner.passive_scan(auth["domain"])
  auth_gate.update_scan_status(intake_id, "passive_done")
  return result, 200


def _report_name(domain: str) -> Path:
  safe = re.sub(r"[^a-zA-Z0-9.-]+", "_", domain).strip("_") or "domain"
  date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
  REPORT_DIR.mkdir(parents=True, exist_ok=True)
  return REPORT_DIR / f"{safe}_{date}.html"


def active_scan(intake_id: str):
  auth = auth_gate.get_authorization(intake_id)
  if not auth or not auth["owns_domain_confirmed"] or not auth["roe_confirmed"]:
    return {"error": "No valid authorization for this intake_id."}, 403
  if not auth["payment_confirmed"]:
    return {"error": "Payment confirmation required before active scan."}, 402

  try:
    result = scanner.scan(auth["domain"])
    result["scan_type"] = "active"
    report_html = report_generator.generate(result)
    report_path = _report_name(auth["domain"])
    report_path.write_text(report_html, encoding="utf-8")
    draft_saved = report_mailer.send_report(result, auth["client_email"], auth["client_name"])
    auth_gate.update_scan_status(intake_id, "active_done")
    return {
      "status": "active_done",
      "report_path": str(report_path),
      "email_draft_saved": draft_saved,
      "result": result,
    }, 200
  except Exception as exc:
    auth_gate.update_scan_status(intake_id, "failed")
    return {"error": str(exc)[:300]}, 500


def health():
  try:
    with auth_gate._conn():  # internal health check; no mutation beyond schema init
      pass
    return {"status": "ok", "db": "connected"}, 200
  except Exception as exc:
    return {"status": "error", "db": str(exc)}, 500


if Flask is not None:
  app = Flask(__name__)

  try:
    from stripe_webhook import stripe_bp
    if stripe_bp is not None:
      app.register_blueprint(stripe_bp, url_prefix="/stripe")
  except Exception as exc:
    print(f"stripe_webhook_mount_failed: {exc}")

  @app.post("/intake")
  def intake_route():
    data = request.get_json(silent=True) or {}
    body, status = create_intake(data, dict(request.headers), request.remote_addr)
    return jsonify(body), status

  @app.post("/scan/passive/<intake_id>")
  def passive_route(intake_id: str):
    body, status = passive_scan(intake_id)
    return jsonify(body), status

  @app.post("/scan/active/<intake_id>")
  def active_route(intake_id: str):
    body, status = active_scan(intake_id)
    return jsonify(body), status

  @app.get("/health")
  def health_route():
    body, status = health()
    return jsonify(body), status


class StdlibHandler(BaseHTTPRequestHandler):
  def _send_json(self, status: int, body: dict):
    raw = json.dumps(body).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(raw)))
    self.end_headers()
    self.wfile.write(raw)

  def _read_json(self) -> dict:
    length = int(self.headers.get("Content-Length", "0") or 0)
    if length <= 0:
      return {}
    return json.loads(self.rfile.read(length).decode("utf-8"))

  def do_GET(self):
    if self.path == "/health":
      body, status = health()
      self._send_json(status, body)
    else:
      self._send_json(404, {"error": "not found"})

  def do_POST(self):
    path = urlparse(self.path).path
    try:
      if path == "/intake":
        body, status = create_intake(self._read_json(), dict(self.headers), self.client_address[0])
      elif path.startswith("/scan/passive/"):
        body, status = passive_scan(path.rsplit("/", 1)[-1])
      elif path.startswith("/scan/active/"):
        body, status = active_scan(path.rsplit("/", 1)[-1])
      elif path == "/stripe/webhook":
        import stripe_webhook
        length = int(self.headers.get("Content-Length", "0") or 0)
        body, status = stripe_webhook.handle_webhook(self.rfile.read(length), dict(self.headers))
      else:
        body, status = {"error": "not found"}, 404
    except Exception as exc:
      body, status = {"error": str(exc)[:300]}, 500
    self._send_json(status, body)


def main() -> None:
  port = int(os.getenv("INTAKE_PORT", "5001"))
  if Flask is not None:
    app.run(host="127.0.0.1", port=port)
    return
  server = ThreadingHTTPServer(("127.0.0.1", port), StdlibHandler)
  print(f"intake_server stdlib fallback listening on http://127.0.0.1:{port}")
  server.serve_forever()


if __name__ == "__main__":
  main()
