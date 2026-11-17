import base64
import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from davidlloyd_signing import (
    DavidLloydHmacSigner,
    ExpiredHmacKey,
    HmacKeyMaterial,
    HmacProvisioningKey,
    InvalidProvisioningResponse,
    InvalidSignerResponse,
    SignerUnavailable,
    canonical_signing_string,
    encode_json_body,
    is_protected_path,
    prepare_signed_json_request,
    safe_traffic_summary,
)


class RecordingSigner:
    def __init__(self):
        self.calls = []

    def sign(self, method, path, body):
        self.calls.append((method, path, body))
        mac = base64.b64encode(b"m" * 32).decode()
        return {
            "X-Timestamp": "1791540093",
            "X-Signature": f"v1 public-key-prefix:{mac}",
        }


class SigningTests(unittest.TestCase):
    def test_json_is_compact_utf8_and_preserves_field_order(self):
        body = encode_json_body({"revenueStream": "CLASS", "useDirectDebit": False})
        self.assertEqual(
            body, b'{"revenueStream":"CLASS","useDirectDebit":false}'
        )

    def test_exact_body_bytes_are_signed_and_returned_for_transport(self):
        signer = RecordingSigner()
        request = prepare_signed_json_request(
            signer,
            "post",
            "/clubs/192/classes/sessions/166345973/hold",
            {"contactId": "encoded", "courseId": 1, "purchaseId": 2},
            {"x-auth-token": "access", "X-Device-Id": "device"},
        )
        self.assertEqual(signer.calls, [("POST", request.path, request.body)])
        self.assertEqual(request.headers["X-Timestamp"], "1791540093")
        self.assertTrue(
            request.headers["X-Signature"].startswith("v1 public-key-prefix:")
        )
        self.assertEqual(request.headers["x-auth-token"], "access")

    def test_missing_signer_blocks_before_protected_request(self):
        with self.assertRaisesRegex(SignerUnavailable, "blockiert"):
            prepare_signed_json_request(None, "POST", "/anything/hold", {"value": 1})

    def test_invalid_signer_output_is_rejected(self):
        class BadSigner:
            def sign(self, method, path, body):
                return {"X-Timestamp": "yesterday", "X-Signature": "static"}

        with self.assertRaises(InvalidSignerResponse):
            prepare_signed_json_request(BadSigner(), "POST", "/anything/hold", {})

    def test_safe_summary_contains_hashes_but_no_secret_values(self):
        request = prepare_signed_json_request(
            RecordingSigner(), "POST", "/anything/hold", {"private": "body"}
        )
        summary = safe_traffic_summary(request)
        self.assertEqual(summary.body_sha256, hashlib.sha256(request.body).hexdigest())
        self.assertEqual(
            summary.key_id_sha256,
            hashlib.sha256(b"public-key-prefix").hexdigest(),
        )
        self.assertEqual(summary.mac_length, 32)
        self.assertNotIn("private", repr(summary))
        self.assertNotIn("public-key-prefix", repr(summary))

    def test_protected_endpoint_detection_ignores_query_string(self):
        self.assertTrue(is_protected_path("/classes/123/hold"))
        self.assertTrue(is_protected_path("/prepare-for-payment?adyenDecomV2=true"))
        self.assertFalse(is_protected_path("/purchases"))

    def test_android_canonical_string_for_json_post(self):
        body = b'{"courseId":1,"purchaseId":2}'
        canonical = canonical_signing_string(
            method="post",
            path="/clubs/192/classes/1/hold?retry=true",
            content_type="application/json",
            body=body,
            device_id="device-123",
            timestamp="1791540093",
        )
        self.assertEqual(
            canonical,
            "\n".join(
                (
                    "POST",
                    "/clubs/192/classes/1/hold?retry=true",
                    "application/json",
                    hashlib.md5(body).hexdigest(),
                    "device-123",
                    "1791540093",
                )
            ),
        )

    def test_bodyless_canonical_string_omits_content_type_and_md5(self):
        canonical = canonical_signing_string(
            method="GET",
            path="/members/me",
            body=b"",
            device_id="device-123",
            timestamp=1791540093,
        )
        self.assertEqual(
            canonical,
            "GET\n/members/me\ndevice-123\n1791540093",
        )

    def test_local_signer_builds_expected_headers_without_exposing_key(self):
        material = HmacKeyMaterial(
            key_id="ABCDEFGHIJKL",
            device_id="device-123",
            hmac_key=b"secret-key-material",
            expiration_timestamp=1791549999,
        )
        signer = DavidLloydHmacSigner(material, clock=lambda: 1791540093)
        body = b'{"courseId":1}'
        headers = signer.sign("post", "/classes/1/hold", body)
        canonical = canonical_signing_string(
            method="POST",
            path="/classes/1/hold",
            content_type="application/json",
            body=body,
            device_id="device-123",
            timestamp="1791540093",
        )
        expected_mac = base64.b64encode(
            hmac.new(
                b"secret-key-material",
                canonical.encode(),
                hashlib.sha256,
            ).digest()
        ).decode()
        self.assertEqual(headers["X-Timestamp"], "1791540093")
        self.assertEqual(headers["X-Device-Id"], "device-123")
        self.assertEqual(
            headers["X-Signature"], f"v1 ABCDEFGHIJKL:{expected_mac}"
        )
        self.assertNotIn("secret-key-material", repr(material))
        self.assertNotIn("secret-key-material", repr(signer))

    def test_prepare_request_accepts_device_id_from_local_signer(self):
        signer = DavidLloydHmacSigner(
            HmacKeyMaterial("ABCDEFGHIJKL", "device-123", b"secret"),
            clock=lambda: 1791540093,
        )
        request = prepare_signed_json_request(
            signer,
            "POST",
            "/classes/1/hold",
            {"courseId": 1},
        )
        self.assertEqual(request.headers["X-Device-Id"], "device-123")

    def test_provisioning_key_has_android_public_key_shape_and_key_id(self):
        provisioning = HmacProvisioningKey.generate()
        public_der = base64.b64decode(provisioning.public_key_base64, validate=True)
        self.assertEqual(provisioning.key_id, provisioning.public_key_base64[:12])
        self.assertEqual(provisioning.request_payload(), {
            "publicKey": provisioning.public_key_base64
        })
        self.assertGreater(len(public_der), 256)
        self.assertNotIn("private", repr(provisioning).lower())

    def test_provisioning_decrypts_both_android_mgf1_variants(self):
        for mgf_hash in (hashes.SHA1(), hashes.SHA256()):
            with self.subTest(mgf_hash=mgf_hash.name):
                provisioning = HmacProvisioningKey.generate()
                plaintext = b"h" * 44
                encrypted = provisioning._private_key.public_key().encrypt(
                    plaintext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=mgf_hash),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                response = {
                    "key": base64.b64encode(encrypted).decode(),
                    "expirationTimestamp": 1791549999,
                }
                material = provisioning.consume_response(
                    response, device_id="device-123"
                )
                self.assertEqual(material.hmac_key, plaintext)
                self.assertEqual(material.key_id, provisioning.key_id)
                self.assertEqual(material.device_id, "device-123")

    def test_invalid_provisioning_response_is_rejected(self):
        provisioning = HmacProvisioningKey.generate()
        with self.assertRaises(InvalidProvisioningResponse):
            provisioning.consume_response(
                {"key": "not base64", "expirationTimestamp": 1},
                device_id="device-123",
            )

    def test_expiration_uses_configurable_safety_leeway(self):
        material = HmacKeyMaterial(
            "ABCDEFGHIJKL", "device-123", b"secret", expiration_timestamp=1000
        )
        self.assertFalse(material.is_expired(now=900))
        self.assertTrue(material.is_expired(now=900, leeway_seconds=100))

    def test_signer_refuses_nearly_expired_key(self):
        signer = DavidLloydHmacSigner(
            HmacKeyMaterial(
                "ABCDEFGHIJKL",
                "device-123",
                b"secret",
                expiration_timestamp=1000,
            ),
            clock=lambda: 971,
        )
        with self.assertRaises(ExpiredHmacKey):
            signer.sign("POST", "/classes/1/hold", b"{}")


if __name__ == "__main__":
    unittest.main()
