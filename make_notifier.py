#!/usr/bin/env python3
"""Fire-and-forget Make.com webhooks for D2D Spirit audit events."""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request


def _load_dotenv() -> None:
  env_path = os.path.join(os.path.dirname(__file__), ".env")
  if not os.path.exists(env_path):
    return
  with open(env_path, encoding="utf-8") as fh:
    for line in fh:
      line = line.strip()
      if not line or line.startswith("#") or "=" not in line:
        continue
      key, value = line.split("=", 1)
      os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()
WEBHOOK_URL = os.getenv("MAKE_INTAKE_WEBHOOK_URL", "")


def _post_async(url: str, payload: dict) -> None:
  body = json.dumps(payload).encode()

  def _send() -> None:
    try:
      req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
      )
      urllib.request.urlopen(req, timeout=5)
    except urllib.error.URLError:
      pass

  threading.Thread(target=_send, daemon=True).start()


def notify_intake(name: str, email: str, domain: str, package: str = "Starter $499") -> None:
  """Fire-and-forget POST to Make.com intake webhook."""
  if not WEBHOOK_URL:
    return
  _post_async(
    WEBHOOK_URL,
    {
      "name": name,
      "email": email,
      "domain": domain,
      "package": package,
    },
  )


def notify_payment(stripe_session_id: str, email: str, domain: str) -> None:
  """Fire-and-forget POST to Make.com payment webhook."""
  payment_url = os.getenv("MAKE_PAYMENT_WEBHOOK_URL", "")
  if not payment_url:
    return
  _post_async(
    payment_url,
    {
      "stripe_session_id": stripe_session_id,
      "email": email,
      "domain": domain,
    },
  )


if __name__ == "__main__":
  import sys

  if "--test" in sys.argv:
    print(
      "MAKE_INTAKE_WEBHOOK_URL:",
      WEBHOOK_URL[:40] + "..." if len(WEBHOOK_URL) > 40 else WEBHOOK_URL or "(not set)",
    )
    notify_intake("Test Client", "test@example.com", "testdomain.com")
    import time

    time.sleep(1)
    print("notify_intake fired (check Make.com for the event)")
