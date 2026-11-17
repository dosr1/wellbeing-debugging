"""Local implementation of the David Lloyd Android v1 request signer.

The implementation mirrors the signer observed in Android app 152.1.0.  It
does not perform login, key-provisioning HTTP requests, or bookings.  Callers
remain responsible for using it only with their own authorized account.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PROTECTED_PATH_SUFFIXES = ("/hold", "/prepare-for-payment")
_SIGNATURE_PATTERN = re.compile(
    r"^v1 (?P<key_id>[^:\s]{1,512}):(?P<mac>[A-Za-z0-9+/]+={0,2})$"
)


class SignerUnavailable(RuntimeError):
    """Raised before any protected provider-side operation is created."""


class InvalidSignerResponse(RuntimeError):
    """Raised when an authorized signer returns unusable headers."""


class InvalidProvisioningResponse(ValueError):
    """Raised when an HMAC-key response cannot be validated or decrypted."""


class ExpiredHmacKey(SignerUnavailable):
    """Raised before signing with expired or nearly expired key material."""


@runtime_checkable
class DavidLloydRequestSigner(Protocol):
    """Adapter implemented by an official SDK or authorized signing service."""

    def sign(self, method: str, path: str, body: bytes) -> Mapping[str, str]:
        """Return fresh X-Timestamp and X-Signature headers for exact body bytes."""


@dataclass(frozen=True, slots=True)
class PreparedSignedRequest:
    method: str
    path: str
    body: bytes
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class SafeTrafficSummary:
    """Non-secret metadata suitable for tests, tickets, and comparisons."""

    method: str
    path: str
    body_length: int
    body_sha256: str
    timestamp_digits: int
    signature_version: str
    key_id_sha256: str
    mac_length: int


@dataclass(frozen=True, slots=True)
class HmacKeyMaterial:
    """Decrypted signer state; the secret is deliberately hidden from repr."""

    key_id: str
    device_id: str
    hmac_key: bytes = dataclass_field(repr=False)
    expiration_timestamp: int | None = None

    def __post_init__(self) -> None:
        if len(self.key_id) != 12 or any(char.isspace() for char in self.key_id):
            raise ValueError("key_id must be the 12-character public-key prefix")
        if not self.device_id:
            raise ValueError("device_id must not be empty")
        if not isinstance(self.hmac_key, bytes) or not self.hmac_key:
            raise ValueError("hmac_key must be non-empty bytes")
        if self.expiration_timestamp is not None and self.expiration_timestamp < 0:
            raise ValueError("expiration_timestamp must not be negative")

    def is_expired(self, now: int | None = None, *, leeway_seconds: int = 0) -> bool:
        if self.expiration_timestamp is None:
            return False
        current = int(time.time()) if now is None else now
        return current + leeway_seconds >= self.expiration_timestamp


@dataclass(frozen=True, slots=True)
class HmacProvisioningKey:
    """Ephemeral RSA key used only to unwrap one server-provided HMAC key."""

    _private_key: rsa.RSAPrivateKey = dataclass_field(repr=False)
    public_key_base64: str

    @classmethod
    def generate(cls, key_size: int = 2048) -> "HmacProvisioningKey":
        if key_size != 2048:
            raise ValueError("Android app 152.1.0 uses an RSA-2048 provisioning key.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(private_key, base64.b64encode(der).decode("ascii"))

    @property
    def key_id(self) -> str:
        """The v1 signature key ID observed in the Android client."""
        return self.public_key_base64[:12]

    def request_payload(self) -> dict[str, str]:
        return {"publicKey": self.public_key_base64}

    def decrypt_hmac_key(self, encrypted_key_base64: str) -> bytes:
        """Decrypt the response key using Android-compatible RSA OAEP.

        Android names the transformation OAEPWithSHA-256AndMGF1Padding. Some
        providers default MGF1 to SHA-1 while others use SHA-256, so both safe
        local interpretations are accepted.
        """
        try:
            encrypted = base64.b64decode(encrypted_key_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise InvalidProvisioningResponse(
                "The encrypted HMAC key is not valid Base64."
            ) from exc
        if len(encrypted) != self._private_key.key_size // 8:
            raise InvalidProvisioningResponse(
                "The encrypted HMAC key is not one RSA ciphertext block."
            )

        for mgf_hash in (hashes.SHA1(), hashes.SHA256()):
            try:
                return self._private_key.decrypt(
                    encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=mgf_hash),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except (ValueError, InvalidKey):
                continue
        raise InvalidProvisioningResponse(
            "The HMAC key could not be decrypted with Android-compatible OAEP."
        )

    def consume_response(
        self,
        response: Mapping[str, Any],
        *,
        device_id: str,
    ) -> HmacKeyMaterial:
        encrypted_key = response.get("key")
        expiration = response.get("expirationTimestamp")
        if not isinstance(encrypted_key, str):
            raise InvalidProvisioningResponse("The response has no string key field.")
        if expiration is not None and (
            not isinstance(expiration, int) or isinstance(expiration, bool)
        ):
            raise InvalidProvisioningResponse(
                "The response expirationTimestamp is not an integer."
            )
        if not device_id:
            raise ValueError("device_id must not be empty")
        return HmacKeyMaterial(
            key_id=self.key_id,
            device_id=device_id,
            hmac_key=self.decrypt_hmac_key(encrypted_key),
            expiration_timestamp=expiration,
        )


@dataclass(frozen=True, slots=True)
class DavidLloydHmacSigner:
    """Pure local HMAC signer matching Android app 152.1.0."""

    material: HmacKeyMaterial = dataclass_field(repr=False)
    clock: Callable[[], float] = dataclass_field(default=time.time, repr=False)
    content_type: str = "application/json"
    expiration_leeway_seconds: int = 30

    def sign(self, method: str, path: str, body: bytes) -> Mapping[str, str]:
        now = int(self.clock())
        if self.material.is_expired(
            now=now,
            leeway_seconds=self.expiration_leeway_seconds,
        ):
            raise ExpiredHmacKey(
                "The HMAC key is expired or too close to expiration; provision a new key."
            )
        timestamp = str(now)
        canonical = canonical_signing_string(
            method=method,
            path=path,
            device_id=self.material.device_id,
            timestamp=timestamp,
            body=body,
            content_type=self.content_type if body else None,
        )
        mac = hashlib_hmac_sha256(self.material.hmac_key, canonical.encode("utf-8"))
        signature = (
            f"v1 {self.material.key_id}:"
            f"{base64.b64encode(mac).decode('ascii')}"
        )
        return {
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "X-Device-Id": self.material.device_id,
        }


def canonical_signing_string(
    *,
    method: str,
    path: str,
    device_id: str,
    timestamp: str | int,
    body: bytes | None = None,
    content_type: str | None = None,
) -> str:
    """Build the newline-delimited Android v1 string-to-sign."""
    if not method or not method.strip():
        raise ValueError("method must not be empty")
    if not path.startswith("/") or "://" in path or "#" in path:
        raise ValueError("path must be an origin-form path without a fragment")
    if not device_id:
        raise ValueError("device_id must not be empty")
    timestamp_text = str(timestamp)
    if not timestamp_text.isdigit():
        raise ValueError("timestamp must contain Unix-second digits only")
    if body and not content_type:
        raise ValueError("content_type is required when body bytes are present")

    components = [method.upper(), path]
    if body:
        components.extend((content_type, hashlib.md5(body).hexdigest()))
    components.extend((device_id, timestamp_text))
    return "\n".join(components)


def hashlib_hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Small wrapper kept separate for straightforward test-vector checks."""
    import hmac

    return hmac.new(key, message, hashlib.sha256).digest()


def encode_json_body(payload: Mapping[str, Any]) -> bytes:
    """Serialize exactly once; preserve insertion order and omit whitespace."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def is_protected_path(path: str) -> bool:
    path_without_query = path.partition("?")[0].rstrip("/")
    return path_without_query.endswith(PROTECTED_PATH_SUFFIXES)


def prepare_signed_json_request(
    signer: DavidLloydRequestSigner | None,
    method: str,
    path: str,
    payload: Mapping[str, Any],
    base_headers: Mapping[str, str] | None = None,
) -> PreparedSignedRequest:
    """Prepare a request without serializing its signed body a second time."""
    normalized_method = method.upper()
    body = encode_json_body(payload)
    if signer is None:
        raise SignerUnavailable(
            "David-Lloyd-Buchungen sind blockiert: Ein autorisierter dynamischer "
            "Request-Signer ist nicht konfiguriert."
        )

    signing_headers = dict(signer.sign(normalized_method, path, body))
    timestamp = signing_headers.get("X-Timestamp")
    signature = signing_headers.get("X-Signature")
    if not timestamp or not timestamp.isdigit():
        raise InvalidSignerResponse("Der Signer lieferte keinen gültigen X-Timestamp.")
    if not signature or _SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise InvalidSignerResponse("Der Signer lieferte keine gültige X-Signature.")

    headers = dict(base_headers or {})
    headers["Content-Type"] = "application/json"
    headers["X-Timestamp"] = timestamp
    headers["X-Signature"] = signature
    signer_device_id = signing_headers.get("X-Device-Id")
    if signer_device_id:
        headers["X-Device-Id"] = signer_device_id
    return PreparedSignedRequest(normalized_method, path, body, headers)


def safe_traffic_summary(request: PreparedSignedRequest) -> SafeTrafficSummary:
    """Describe a signed request without exposing body, key ID, or MAC."""
    signature = request.headers.get("X-Signature", "")
    match = _SIGNATURE_PATTERN.fullmatch(signature)
    if match is None:
        raise InvalidSignerResponse("Das Signaturformat kann nicht ausgewertet werden.")
    try:
        mac = base64.b64decode(match.group("mac"), validate=True)
    except ValueError as exc:
        raise InvalidSignerResponse("Der Signatur-MAC ist kein gültiges Base64.") from exc
    timestamp = request.headers.get("X-Timestamp", "")
    return SafeTrafficSummary(
        method=request.method,
        path=request.path,
        body_length=len(request.body),
        body_sha256=hashlib.sha256(request.body).hexdigest(),
        timestamp_digits=len(timestamp),
        signature_version="v1",
        key_id_sha256=hashlib.sha256(match.group("key_id").encode()).hexdigest(),
        mac_length=len(mac),
    )
