#!/usr/bin/env python3
"""Stripe webhook handler for D2D Spirit intake payments."""

from __future__ import annotations

import json
import os
from typing import Any

import auth_gate
from make_notifier import notify_payment

try:
  from flask import Blueprint, jsonify, request
except Exception:  # Flask is optional in local stdlib fallback mode.
  Blueprint = None
  jsonify = None
  request = None

try:
  import stripe
except Exception:
  stripe = None


def _load_dotenv() -> None:
  env = os.path.join(os.path.dirname(__file__), ".env")
  if not os.path.exists(env):
    return
  for line in open(env, encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
      continue
    key, value = line.split("=", 1)
    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _metadata_intake_id(event: dict[str, Any]) -> tuple[str, str]:
  obj = event.get("data", {}).get("object", {})
  metadata = obj.get("metadata") or {}
  return str(metadata.get("intake_id") or ""), str(obj.get("id") or "")


def handle_webhook(payload: bytes, headers: dict[str, str]) -> tuple[dict[str, Any], int]:
  _load_dotenv()
  secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
  if not secret:
    return {"error": "STRIPE_WEBHOOK_SECRET not configured"}, 500
  if stripe is None:
    return {"error": "stripe package not installed"}, 503

  try:
    event = stripe.Webhook.construct_event(
      payload,
      headers.get("Stripe-Signature", ""),
      secret,
    )
  except Exception:
    return {"error": "invalid signature"}, 400

  if event.get("type") == "payment_intent.succeeded":
    intake_id, payment_intent_id = _metadata_intake_id(event)
    if intake_id and payment_intent_id:
      auth_gate.confirm_payment(intake_id, payment_intent_id)
      auth = auth_gate.get_authorization(intake_id) or {}
      notify_payment(
        stripe_session_id=str(event.get("id") or payment_intent_id),
        email=str(auth.get("client_email") or ""),
        domain=str(auth.get("domain") or ""),
      )
  return {"received": True}, 200


if Blueprint is not None:
  stripe_bp = Blueprint("stripe_webhook", __name__)

  @stripe_bp.post("/webhook")
  def webhook():
    body, status = handle_webhook(request.get_data(), dict(request.headers))
    return jsonify(body), status
else:
  stripe_bp = None


if __name__ == "__main__":
  sample = {"type": "ignored", "data": {"object": {}}}
  print(json.dumps(sample))
