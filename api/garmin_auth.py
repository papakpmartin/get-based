"""Server-side Garmin Connect authentication handler for getbased.

This Vercel Python serverless function handles the Garmin OAuth1 → OAuth2
exchange using the proven `garth` library (v0.8.0). The JavaScript proxy
forwards `garmin_credentials` (email/password login) and
`garmin_token_refresh` (OAuth1 token refresh) payloads here so credentials
and long-lived refresh state never reach the browser.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any
from urllib.parse import urlencode, urljoin

import cloudscraper
from garth.auth_tokens import OAuth1Token, OAuth2Token
from garth.exc import MFARequired, GarminConnectAuthenticationError
from garth.http import Client
from garth.sso import exchange, login

# ── Vercel function configuration ───────────────────────────────
# Runtime: Python 3.9 (Vercel default at time of writing)
# maxDuration is configured in vercel.json as 60 seconds.

CORS_HEADERS_BASE = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Cache-Control": "no-store",
    "Vary": "Origin",
}

ALLOWED_ORIGINS = {
    "https://app.getbased.health",
    "https://getbased.health",
    "https://www.getbased.health",
    "https://beta.getbased.health",
    "https://get-based.vercel.app",
    "https://get-based-managed-subscription-v2.vercel.app",
}


def _allowed_origin(origin: str) -> str:
    """Return the origin if it is allowed, otherwise ''."""
    return origin if origin in ALLOWED_ORIGINS else ""


def _cors_headers(origin: str) -> dict[str, str]:
    headers = dict(CORS_HEADERS_BASE)
    allowed = _allowed_origin(origin)
    if allowed:
        headers["Access-Control-Allow-Origin"] = allowed
    return headers


def _json_response(
    status: int,
    body: dict[str, Any],
    origin: str,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = _cors_headers(origin)
    headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body),
    }


def _oauth1_to_refresh_token(oauth1: OAuth1Token) -> str:
    """Serialize the OAuth1 token as a base64-encoded JSON refresh token."""
    payload = {
        "oauth_token": oauth1.oauth_token,
        "oauth_token_secret": oauth1.oauth_token_secret,
    }
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def _refresh_token_to_oauth1(refresh_token: str) -> OAuth1Token:
    """Deserialize the base64-encoded OAuth1 refresh token."""
    raw = base64.b64decode(refresh_token, validate=True)
    payload = json.loads(raw.decode("utf-8"))
    return OAuth1Token(
        oauth_token=payload["oauth_token"],
        oauth_token_secret=payload["oauth_token_secret"],
    )


def _client_with_cloudscraper() -> Client:
    """Create a new garth Client using cloudscraper to bypass Cloudflare."""
    client = Client(domain="garmin.com")
    client.sess = cloudscraper.create_scraper()
    return client


def _token_response(
    oauth1: OAuth1Token,
    oauth2: OAuth2Token,
    origin: str,
) -> dict[str, Any]:
    return _json_response(
        200,
        {
            "access_token": oauth2.access_token,
            "refresh_token": _oauth1_to_refresh_token(oauth1),
            "expires_in": oauth2.expires_in,
            "refresh_token_expires_in": getattr(
                oauth2, "refresh_token_expires_in", None
            ),
            "token_type": oauth2.token_type,
            # Garmin does not expose a stable numeric user id in the token
            # response; callers can fetch profile via connectapi if needed.
            "user_id": None,
        },
        origin,
    )


def _error_response(status: int, message: str, origin: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": message}
    if extra:
        body.update(extra)
    return _json_response(status, body, origin)


def _handle_login(body: dict[str, Any], origin: str) -> dict[str, Any]:
    email = body.get("email")
    password = body.get("password")
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        return _error_response(400, "Garmin login requires email and password.", origin)

    client = _client_with_cloudscraper()
    try:
        result = login(email, password, client=client, return_on_mfa=True)
    except MFARequired as exc:
        return _error_response(
            401,
            "MFA required",
            origin,
            {"mfa_required": True, "mfa_method": getattr(exc, "mfa_method", "email")},
        )
    except GarminConnectAuthenticationError as exc:
        # Avoid surfacing internal details; do not include email/password.
        return _error_response(401, "Invalid Garmin credentials.", origin)
    except Exception as exc:
        # Log the class name only — never the credentials.
        sys.stderr.write(f"Garmin login error: {type(exc).__name__}: {exc}\n")
        return _error_response(502, "Garmin authentication service unavailable.", origin)

    # garth.login() with return_on_mfa=True can return either a tuple of tokens
    # or a tuple indicating MFA is required. Normalize safely.
    if result is None:
        return _error_response(401, "Invalid Garmin credentials.", origin)

    # MFA sentinel shape used by some garth versions
    if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
        return _error_response(
            401,
            "MFA required",
            origin,
            {"mfa_required": True, "mfa_method": "email"},
        )

    try:
        oauth1, oauth2 = result
    except Exception:
        return _error_response(502, "Unexpected Garmin authentication response.", origin)

    if not isinstance(oauth1, OAuth1Token) or not isinstance(oauth2, OAuth2Token):
        return _error_response(502, "Unexpected Garmin authentication response.", origin)

    return _token_response(oauth1, oauth2, origin)


def _handle_refresh(body: dict[str, Any], origin: str) -> dict[str, Any]:
    refresh_token = body.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        return _error_response(400, "Garmin refresh requires refresh_token.", origin)

    try:
        oauth1 = _refresh_token_to_oauth1(refresh_token)
    except Exception:
        return _error_response(400, "Invalid Garmin refresh token.", origin)

    client = _client_with_cloudscraper()
    try:
        oauth2 = exchange(oauth1, client=client)
    except Exception as exc:
        sys.stderr.write(f"Garmin refresh error: {type(exc).__name__}: {exc}\n")
        return _error_response(502, "Garmin token refresh failed.", origin)

    if not isinstance(oauth2, OAuth2Token):
        return _error_response(502, "Unexpected Garmin refresh response.", origin)

    return _token_response(oauth1, oauth2, origin)


def _handle_proxy(body: dict[str, Any], origin: str) -> dict[str, Any]:
    """Forward a generic Garmin API request.

    The OAuth2 Bearer token is supplied by the caller in `headers`. This handler
    injects Cloudflare-evading session state if the caller did not already
    provide a usable cookie jar, and forwards the request to Garmin Connect.
    """
    url = body.get("url")
    method = body.get("method") or "GET"
    headers = body.get("headers") or {}
    req_body = body.get("body")

    if not isinstance(url, str) or not url:
        return _error_response(400, "Garmin proxy requires url.", origin)

    if not isinstance(headers, dict) or isinstance(headers, list):
        return _error_response(400, "Garmin proxy headers must be an object.", origin)

    # Only admit Garmin origins.
    if not (
        url.startswith("https://connect.garmin.com/")
        or url.startswith("https://connectapi.garmin.com/")
    ):
        return _error_response(403, "Garmin proxy URL not allowed.", origin)

    method = str(method).upper()
    if method not in {"GET", "POST", "PUT"}:
        return _error_response(405, "Garmin proxy method not allowed.", origin)

    # cloudscraper manages TLS fingerprinting and Cloudflare cookies.
    scraper = cloudscraper.create_scraper()

    # Ensure a content-type default for body-bearing methods.
    safe_headers = {str(k): str(v) for k, v in headers.items()}
    if method != "GET" and "content-type" not in {k.lower() for k in safe_headers}:
        safe_headers["Content-Type"] = "application/json"

    try:
        if method == "GET":
            upstream = scraper.get(url, headers=safe_headers, timeout=30)
        elif method == "POST":
            data = req_body if isinstance(req_body, str) else json.dumps(req_body) if req_body is not None else None
            upstream = scraper.post(url, headers=safe_headers, data=data, timeout=30)
        else:  # PUT
            data = req_body if isinstance(req_body, str) else json.dumps(req_body) if req_body is not None else None
            upstream = scraper.put(url, headers=safe_headers, data=data, timeout=30)
    except Exception as exc:
        sys.stderr.write(f"Garmin proxy error: {type(exc).__name__}: {exc}\n")
        return _error_response(502, "Garmin proxy upstream failed.", origin)

    response_headers = dict(upstream.headers)
    # Remove hop-by-hop headers that Vercel/ALB will re-add.
    for hop in ("connection", "content-length", "transfer-encoding", "upgrade", "keep-alive", "te", "trailer"):
        response_headers.pop(hop, None)
        response_headers.pop(hop.title(), None)
    response_headers.update(_cors_headers(origin))
    response_headers["Content-Type"] = response_headers.get("Content-Type", "application/json")

    return {
        "statusCode": upstream.status_code,
        "headers": response_headers,
        "body": upstream.text,
    }


def _handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    origin = ""
    try:
        headers = event.get("headers") or {}
        origin = str(headers.get("origin") or headers.get("Origin") or "").strip()
    except Exception:
        pass

    if event.get("httpMethod") == "OPTIONS":
        response_headers = _cors_headers(origin)
        if _allowed_origin(origin):
            response_headers["Access-Control-Allow-Origin"] = _allowed_origin(origin)
        return {
            "statusCode": 204,
            "headers": response_headers,
            "body": "",
        }

    if event.get("httpMethod") and event.get("httpMethod") != "POST":
        return _error_response(405, "Method not allowed. Use POST.", origin)

    try:
        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        payload = json.loads(raw_body)
    except Exception:
        return _error_response(400, "Invalid JSON body.", origin)

    if not isinstance(payload, dict):
        return _error_response(400, "Payload must be an object.", origin)

    action = payload.get("action")
    if action == "login":
        return _handle_login(payload, origin)
    if action == "refresh":
        return _handle_refresh(payload, origin)
    if action == "proxy":
        return _handle_proxy(payload, origin)

    return _error_response(
        400,
        'Unsupported action. Use "login", "refresh", or "proxy".',
        origin,
    )


# Vercel serverless entry point for Python functions.
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return _handler(event, context)
