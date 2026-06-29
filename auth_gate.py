#!/usr/bin/env python3
"""Authorization gate for D2D Spirit security audits.

Active scans must not run unless this database has explicit authorization and,
for paid audits, confirmed payment.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "authorizations.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  client_name TEXT NOT NULL,
  client_email TEXT NOT NULL,
  owns_domain_confirmed BOOLEAN NOT NULL,
  roe_confirmed BOOLEAN NOT NULL,
  submitted_at TEXT NOT NULL,
  payment_confirmed BOOLEAN DEFAULT FALSE,
  payment_confirmed_at TEXT,
  stripe_payment_intent TEXT,
  scan_status TEXT DEFAULT 'pending',
  created_ip TEXT
);
"""


def _now() -> str:
  return datetime.now(timezone.utc).isoformat()


def normalize_domain(domain: str) -> str:
  value = (domain or "").strip().lower()
  value = value.removeprefix("https://").removeprefix("http://")
  value = value.split("/", 1)[0].split(":", 1)[0]
  return value.strip(".")


def _conn() -> sqlite3.Connection:
  DB_PATH.parent.mkdir(parents=True, exist_ok=True)
  conn = sqlite3.connect(DB_PATH)
  conn.row_factory = sqlite3.Row
  conn.execute(SCHEMA)
  conn.commit()
  return conn


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
  if row is None:
    return None
  out = dict(row)
  for key in ("owns_domain_confirmed", "roe_confirmed", "payment_confirmed"):
    out[key] = bool(out.get(key))
  return out


def create_authorization(
  domain: str,
  client_name: str,
  client_email: str,
  *,
  owns_confirmed: bool,
  roe_confirmed: bool,
  ip: str | None,
) -> str:
  auth_id = str(uuid.uuid4())
  normalized = normalize_domain(domain)
  with _conn() as conn:
    conn.execute(
      """
      INSERT INTO authorizations (
        id, domain, client_name, client_email, owns_domain_confirmed,
        roe_confirmed, submitted_at, created_ip
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      """,
      (
        auth_id,
        normalized,
        client_name.strip(),
        client_email.strip(),
        int(bool(owns_confirmed)),
        int(bool(roe_confirmed)),
        _now(),
        ip or "",
      ),
    )
  return auth_id


def confirm_payment(auth_id: str, stripe_payment_intent: str) -> None:
  with _conn() as conn:
    conn.execute(
      """
      UPDATE authorizations
      SET payment_confirmed=1, payment_confirmed_at=?, stripe_payment_intent=?
      WHERE id=?
      """,
      (_now(), stripe_payment_intent, auth_id),
    )


def update_scan_status(auth_id: str, status: str) -> None:
  if status not in {"pending", "passive_done", "active_done", "failed"}:
    raise ValueError(f"invalid scan_status: {status}")
  with _conn() as conn:
    conn.execute("UPDATE authorizations SET scan_status=? WHERE id=?", (status, auth_id))


def get_authorization(auth_id: str) -> dict[str, Any] | None:
  with _conn() as conn:
    row = conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone()
  return _row_to_dict(row)


def get_latest_for_domain(domain: str) -> dict[str, Any] | None:
  normalized = normalize_domain(domain)
  with _conn() as conn:
    row = conn.execute(
      """
      SELECT * FROM authorizations
      WHERE domain=? AND owns_domain_confirmed=1 AND roe_confirmed=1
      ORDER BY submitted_at DESC
      LIMIT 1
      """,
      (normalized,),
    ).fetchone()
  return _row_to_dict(row)


def list_authorizations() -> list[dict[str, Any]]:
  with _conn() as conn:
    rows = conn.execute("SELECT * FROM authorizations ORDER BY submitted_at DESC").fetchall()
  return [row for row in (_row_to_dict(r) for r in rows) if row]


def is_authorized(domain: str) -> bool:
  normalized = normalize_domain(domain)
  with _conn() as conn:
    row = conn.execute(
      """
      SELECT 1 FROM authorizations
      WHERE domain=? AND owns_domain_confirmed=1 AND roe_confirmed=1
      LIMIT 1
      """,
      (normalized,),
    ).fetchone()
  return row is not None


if __name__ == "__main__":
  with _conn():
    pass
  print(f"authorization db ready: {DB_PATH}")
