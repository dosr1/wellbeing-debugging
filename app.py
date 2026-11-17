#!/usr/bin/env python3
"""Local, dependency-free PKCE login assistant for the David Lloyd mobile API.

The assistant deliberately keeps OAuth secrets in memory only and never logs
request bodies, authorization codes, or returned tokens.
"""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import truststore

from davidlloyd_signing import (
    DavidLloydHmacSigner,
    HmacProvisioningKey,
    prepare_signed_json_request,
)


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
OAUTH_BASE = "https://digitalmanager.davidlloyd.co.uk/oauth2/default"
OKTA_ORIGIN = "https://digitalmanager.davidlloyd.co.uk"
AUTHN_URL = f"{OKTA_ORIGIN}/api/v1/authn"
AUTHORIZE_URL = f"{OAUTH_BASE}/v1/authorize"
TOKEN_URL = f"{OAUTH_BASE}/v1/token"
REDIRECT_URI = "uk.co.davidlloyd.mobile-app:/login"
DEFAULT_SCOPE = "openid profile offline_access"
MAX_BODY_BYTES = 32 * 1024
# Use the native OS trust store.  On managed macOS installations this includes
# locally trusted enterprise/interception CAs which are intentionally absent
# from certifi's public-CA-only bundle.  Verification and hostname checks stay
# enabled by PROTOCOL_TLS_CLIENT.
TLS_CONTEXT = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
MOBILE_API_ORIGIN = "https://mobile-app-back.davidlloyd.co.uk"

# One deliberately narrow, user-confirmed booking target. Keeping the target
# server-side prevents a stray browser request from changing what gets booked.
BOOKING_TARGET = {
    "site_id": 192,
    "course_instance_id": 166345973,
    "course_id": 138325605,
    "contact_id": "QVNQUklBNDAxNDUwMTc=",
}
BOOKING_DEVICE_ID = "FB51071E-39A3-4BAB-904F-9537AD1E2E76"


@dataclass(slots=True)
class LoginFlow:
    client_id: str
    verifier: str
    state: str
    nonce: str
    created_at: float


def b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorize_url(flow: LoginFlow, session_token: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": flow.client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "response_mode": "query",
            "scope": DEFAULT_SCOPE,
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge_method": "S256",
            "code_challenge": b64url_sha256(flow.verifier),
            "sessionToken": session_token,
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        return None


def authorize_code(flow: LoginFlow, session_token: str) -> str:
    """Obtain and validate the authorization code without opening a browser."""
    request = urllib.request.Request(
        build_authorize_url(flow, session_token),
        headers={"Accept": "text/html", "User-Agent": "WellbeingBot-Login-Assistant/0.2"},
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=TLS_CONTEXT),
        _NoRedirect(),
    )
    try:
        with opener.open(request, timeout=15) as response:
            status = response.status
            location = response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        if exc.code != HTTPStatus.FOUND:
            raise RuntimeError("Die Anbieter-Autorisierung konnte nicht abgeschlossen werden.") from None
        status = exc.code
        location = exc.headers.get("Location")
    except (ValueError, urllib.error.URLError, TimeoutError):
        raise RuntimeError("Die Anbieter-Autorisierung war nicht zuverlässig erreichbar.") from None

    if status != HTTPStatus.FOUND or not isinstance(location, str) or not location:
        raise RuntimeError("Die Anbieter-Autorisierung konnte nicht abgeschlossen werden.")
    try:
        return parse_callback_url(location, flow.state)
    except ValueError:
        raise RuntimeError("Die Anbieter-Autorisierung konnte nicht abgeschlossen werden.") from None


def authenticate(username: str, password: str) -> str:
    """Perform Okta primary authentication and return a one-use session token."""
    body = json.dumps(
        {
            "username": username,
            "password": password,
            "options": {
                "multiOptionalFactorEnroll": False,
                "warnBeforePasswordExpired": False,
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        AUTHN_URL,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "WellbeingBot-Login-Assistant/0.2",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=TLS_CONTEXT) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == HTTPStatus.UNAUTHORIZED:
            raise ValueError("Benutzername oder Passwort wurden nicht akzeptiert.") from None
        if exc.code == HTTPStatus.TOO_MANY_REQUESTS:
            raise RuntimeError("Zu viele Anmeldeversuche. Bitte später erneut versuchen.") from None
        raise RuntimeError(f"Die Anbieter-Anmeldung antwortete mit HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError("Die Anbieter-Anmeldung war nicht zuverlässig erreichbar.") from None

    if not isinstance(payload, dict):
        raise RuntimeError("Die Anbieter-Anmeldung lieferte eine unerwartete Antwort.")
    status = payload.get("status")
    session_token = payload.get("sessionToken")
    if status == "SUCCESS" and isinstance(session_token, str) and session_token:
        return session_token
    if status in {"MFA_REQUIRED", "MFA_CHALLENGE"}:
        raise ValueError("Für dieses Konto ist eine zusätzliche Bestätigung erforderlich; MFA wird noch nicht unterstützt.")
    if status in {"PASSWORD_EXPIRED", "PASSWORD_WARN", "LOCKED_OUT"}:
        raise ValueError("Das Konto benötigt eine Aktion direkt bei David Lloyd, bevor die Anmeldung möglich ist.")
    raise ValueError("Die Anmeldung konnte nicht abgeschlossen werden.")


def parse_callback_url(raw_url: str, expected_state: str) -> str:
    raw_url = raw_url.strip()
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError as exc:
        raise ValueError("Die Rückgabe-URL ist ungültig.") from exc
    if (
        raw_url.partition("?")[0] != REDIRECT_URI
        or "#" in raw_url
        or parsed.scheme != "uk.co.davidlloyd.mobile-app"
        or parsed.netloc
        or parsed.path != "/login"
        or parsed.fragment
    ):
        raise ValueError("Die Rückgabe-URL hat nicht das erwartete David-Lloyd-Format.")
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if params.get("error"):
        raise ValueError("Die Anmeldung wurde vom Anbieter abgebrochen oder abgelehnt.")
    state = params.get("state", [""])[0]
    try:
        state_matches = secrets.compare_digest(state.encode("ascii"), expected_state.encode("ascii"))
    except UnicodeEncodeError:
        state_matches = False
    if not state_matches:
        raise ValueError("Die State-Prüfung ist fehlgeschlagen. Bitte neu beginnen.")
    code = params.get("code", [""])[0]
    if not code or len(code) > 4096:
        raise ValueError("Die Rückgabe-URL enthält keinen gültigen Authorization Code.")
    return code


def exchange_code(flow: LoginFlow, code: str) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": flow.client_id,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": flow.verifier,
        }
    ).encode("ascii")
    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": "WellbeingBot-Login-Assistant/0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=TLS_CONTEXT) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        # Never return the upstream body: it could contain sensitive context.
        raise RuntimeError(f"Der Token-Endpunkt antwortete mit HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError("Der Token-Endpunkt war nicht zuverlässig erreichbar.") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
        raise RuntimeError("Der Token-Endpunkt lieferte keine erwartete Token-Antwort.")
    return payload


def jwt_hints(token: str) -> dict[str, Any]:
    """Read non-security-critical JWT hints without claiming verification."""
    try:
        middle = token.split(".")[1]
        padded = middle + "=" * (-len(middle) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    allowed = {"exp", "iat", "auth_time", "contactId"}
    return {key: payload[key] for key in allowed if key in payload}


def _mobile_json(
    method: str,
    path: str,
    *,
    access_token: str | None = None,
    body_payload: dict[str, Any] | None = None,
    signer: DavidLloydHmacSigner | None = None,
    safe_cache: bool = False,
) -> Any:
    headers = {
        "Accept": "application/json",
        "X-Device-Id": BOOKING_DEVICE_ID,
        "User-Agent": "WellbeingBot-Booking-Assistant/0.1",
    }
    if access_token:
        headers["x-auth-token"] = access_token
    body: bytes | None = None
    if body_payload is not None:
        if signer is None:
            body = json.dumps(body_payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            prepared = prepare_signed_json_request(
                signer, method, path, body_payload, headers
            )
            body = prepared.body
            headers = dict(prepared.headers)
    if safe_cache:
        headers["X-Safe-Cache-Control-Client"] = "true"
    request = urllib.request.Request(
        f"{MOBILE_API_ORIGIN}{path}",
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=20, context=TLS_CONTEXT) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"David-Lloyd-API antwortete bei {path} mit HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError(f"David-Lloyd-API war bei {path} nicht zuverlässig erreichbar.") from None


def _find_course_entries(value: Any, course_instance_id: int) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        details = value.get("details")
        direct_id = value.get("courseInstanceId")
        nested_id = details.get("courseInstanceId") if isinstance(details, dict) else None
        if direct_id == course_instance_id or nested_id == course_instance_id:
            found.append(value)
        for child in value.values():
            found.extend(_find_course_entries(child, course_instance_id))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_course_entries(child, course_instance_id))
    return found


def _first_int(value: Any, names: set[str]) -> int | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names and isinstance(child, int) and not isinstance(child, bool):
                return child
        for child in value.values():
            match = _first_int(child, names)
            if match is not None:
                return match
    elif isinstance(value, list):
        for child in value:
            match = _first_int(child, names)
            if match is not None:
                return match
    return None


def book_confirmed_course(access_token: str) -> dict[str, Any]:
    target = BOOKING_TARGET
    bookings_path = "/members/me/bookings?include-others-i-can-book-for=1"
    existing = _mobile_json("GET", bookings_path, access_token=access_token)
    matching = _find_course_entries(existing, target["course_instance_id"])
    if any(str(item.get("status", "")).lower() == "confirmed" for item in matching):
        return {"result": "already_confirmed"}

    provisioning = HmacProvisioningKey.generate()
    provisioned = _mobile_json(
        "POST", "/hmac/key", body_payload=provisioning.request_payload()
    )
    material = provisioning.consume_response(
        provisioned, device_id=BOOKING_DEVICE_ID
    )
    signer = DavidLloydHmacSigner(material)

    purchase = _mobile_json(
        "POST",
        "/purchases",
        access_token=access_token,
        body_payload={"siteId": target["site_id"]},
        signer=signer,
    )
    purchase_id = purchase.get("purchaseId") if isinstance(purchase, dict) else None
    if not isinstance(purchase_id, int) or isinstance(purchase_id, bool):
        raise RuntimeError("Die Purchase-Antwort enthielt keine gültige purchaseId.")

    hold_path = (
        f"/clubs/{target['site_id']}/classes/sessions/"
        f"{target['course_instance_id']}/hold"
    )
    hold = _mobile_json(
        "POST",
        hold_path,
        access_token=access_token,
        body_payload={
            "contactId": target["contact_id"],
            "courseId": target["course_id"],
            "purchaseId": purchase_id,
        },
        signer=signer,
        safe_cache=True,
    )
    price = _first_int(hold, {"priceInPennies", "classPrice"})
    if price is not None and price > 0:
        return {"result": "payment_required", "price_in_pennies": price}

    prepare_path = (
        f"/members/me/purchases/{purchase_id}/prepare-for-payment"
        "?adyenDecomV2=true"
    )
    prepared = _mobile_json(
        "POST",
        prepare_path,
        access_token=access_token,
        body_payload={
            "locale": "de_DE",
            "revenueStream": "CLASS",
            "useDirectDebit": False,
        },
        signer=signer,
        safe_cache=True,
    )
    if isinstance(prepared, dict) and prepared.get("needsPayment") is True:
        return {"result": "payment_required"}

    verified = _mobile_json("GET", bookings_path, access_token=access_token)
    confirmed = [
        item
        for item in _find_course_entries(verified, target["course_instance_id"])
        if str(item.get("status", "")).lower() == "confirmed"
    ]
    if not confirmed:
        return {"result": "not_confirmed"}
    reference = confirmed[0].get("bookingReference")
    return {
        "result": "confirmed",
        "booking_reference": reference if isinstance(reference, str) else "",
    }


def check_booking_state(access_token: str) -> dict[str, Any]:
    bookings = _mobile_json(
        "GET",
        "/members/me/bookings?include-others-i-can-book-for=1",
        access_token=access_token,
    )
    entries = _find_course_entries(bookings, BOOKING_TARGET["course_instance_id"])
    states: list[dict[str, str]] = []
    for item in entries:
        status = item.get("status")
        reference = item.get("bookingReference")
        state = {
            "status": status if isinstance(status, str) else "unknown",
            "booking_reference": reference if isinstance(reference, str) else "",
        }
        if state not in states:
            states.append(state)
    return {"result": "state", "entries": states}


class Handler(BaseHTTPRequestHandler):
    server_version = "LoginAssistant"

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately avoid the default request log because callback URLs carry codes.
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        super().end_headers()

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            candidate = (STATIC / path.removeprefix("/static/")).resolve()
            if STATIC.resolve() not in candidate.parents:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Nicht gefunden."})
                return
            media_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self._serve_file(candidate, f"{media_type}; charset=utf-8")
        elif path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Nicht gefunden."})

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/flow":
            self._start_flow()
        elif path == "/api/book-confirmed-course":
            self._book_confirmed_course()
        elif path == "/api/check-booking-state":
            self._check_booking_state()
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Nicht gefunden."})

    def _start_flow(self) -> None:
        data = self._read_json()
        if data is None:
            return
        client_id = str(data.get("client_id", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not client_id or len(client_id) > 256 or any(ch.isspace() for ch in client_id):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Bitte eine gültige Mobile Client-ID eingeben."})
            return
        if not username or len(username) > 320 or not password or len(password) > 1024:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Bitte Benutzername und Passwort vollständig eingeben."})
            return
        try:
            session_token = authenticate(username, password)
        except ValueError as exc:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        try:
            flow = LoginFlow(
                client_id=client_id,
                verifier=secrets.token_urlsafe(64),
                state=secrets.token_urlsafe(32),
                nonce=secrets.token_urlsafe(32),
                created_at=time.monotonic(),
            )
            code = authorize_code(flow, session_token)
            tokens = exchange_code(flow, code)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        result = {
            "access_token": tokens.get("access_token", ""),
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens.get("id_token", ""),
            "token_type": tokens.get("token_type", ""),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope", ""),
            "jwt_hints": jwt_hints(tokens["access_token"]),
        }
        self._json(
            HTTPStatus.OK,
            result,
        )

    def _book_confirmed_course(self) -> None:
        data = self._read_json()
        if data is None:
            return
        if self.headers.get("X-Booking-Confirmation") != "Power Interval 2026-10-16 08:00":
            self._json(HTTPStatus.FORBIDDEN, {"error": "Buchungsbestätigung fehlt."})
            return
        access_token = str(data.get("access_token", ""))
        if not access_token or len(access_token) > 16_384:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Access-Token fehlt."})
            return
        try:
            result = book_confirmed_course(access_token)
        except RuntimeError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        except Exception:
            self._json(
                HTTPStatus.BAD_GATEWAY,
                {"error": "Der Buchungsablauf ist unerwartet fehlgeschlagen."},
            )
            return
        self._json(HTTPStatus.OK, result)

    def _check_booking_state(self) -> None:
        data = self._read_json()
        if data is None:
            return
        access_token = str(data.get("access_token", ""))
        if not access_token or len(access_token) > 16_384:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Access-Token fehlt."})
            return
        try:
            result = check_booking_state(access_token)
        except RuntimeError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        self._json(HTTPStatus.OK, result)

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Ungültige Anfrage."})
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Ungültige JSON-Anfrage."})
            return None
        if not isinstance(data, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Ungültige Anfrage."})
            return None
        return data

    def _serve_file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            self._json(HTTPStatus.NOT_FOUND, {"error": "Nicht gefunden."})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: dict[str, Any], cookie: str | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = os.environ.get("DL_ASSISTANT_HOST", "127.0.0.1")
    port = int(os.environ.get("DL_ASSISTANT_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"David-Lloyd Login-Assistent: http://{host}:{port}")
    print("Lokale Sitzung; Zugangsdaten und Tokens werden nicht protokolliert.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
