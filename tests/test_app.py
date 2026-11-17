from email.message import Message
import json
import unittest
import urllib.parse
from unittest import mock

import app


class PkceTests(unittest.TestCase):
    def setUp(self):
        self.flow = app.LoginFlow(
            client_id="client-123",
            verifier="verifier-value",
            state="expected-state",
            nonce="nonce-value",
            created_at=0,
        )

    def authorize_redirect(self, location):
        headers = Message()
        headers["Location"] = location
        return urllib.error.HTTPError(
            app.AUTHORIZE_URL,
            302,
            "Found",
            headers,
            None,
        )

    def test_authorize_url_contains_required_pkce_fields(self):
        parsed = urllib.parse.urlsplit(app.build_authorize_url(self.flow, "one-time-session"))
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["state"], ["expected-state"])
        self.assertEqual(query["redirect_uri"], [app.REDIRECT_URI])
        self.assertEqual(query["sessionToken"], ["one-time-session"])

    def test_callback_rejects_wrong_state(self):
        with self.assertRaisesRegex(ValueError, "State"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app:/login?code=secret&state=wrong",
                "expected-state",
            )

    def test_callback_rejects_redirect_with_authority(self):
        with self.assertRaisesRegex(ValueError, "David-Lloyd-Format"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app://unexpected/login?code=secret&state=expected-state",
                "expected-state",
            )

    def test_callback_rejects_redirect_with_empty_authority(self):
        with self.assertRaisesRegex(ValueError, "David-Lloyd-Format"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app:///login?code=secret&state=expected-state",
                "expected-state",
            )

    def test_callback_rejects_redirect_with_fragment(self):
        with self.assertRaisesRegex(ValueError, "David-Lloyd-Format"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app:/login?code=secret&state=expected-state#extra",
                "expected-state",
            )

    def test_callback_rejects_redirect_with_empty_fragment(self):
        with self.assertRaisesRegex(ValueError, "David-Lloyd-Format"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app:/login?code=secret&state=expected-state#",
                "expected-state",
            )

    def test_callback_rejects_non_ascii_state(self):
        with self.assertRaisesRegex(ValueError, "State"):
            app.parse_callback_url(
                "uk.co.davidlloyd.mobile-app:/login?code=secret&state=%C3%A4",
                "expected-state",
            )

    def test_callback_accepts_expected_custom_scheme(self):
        result = app.parse_callback_url(
            "uk.co.davidlloyd.mobile-app:/login?code=secret&state=expected-state",
            "expected-state",
        )
        self.assertEqual(result, "secret")

    @mock.patch("app.urllib.request.build_opener")
    def test_authorize_code_accepts_valid_redirect(self, build_opener):
        build_opener.return_value.open.side_effect = self.authorize_redirect(
            "uk.co.davidlloyd.mobile-app:/login?code=secret&state=expected-state"
        )

        result = app.authorize_code(self.flow, "one-time-session")

        self.assertEqual(result, "secret")

    @mock.patch("app.urllib.request.build_opener")
    def test_authorize_code_rejects_redirect_with_wrong_state(self, build_opener):
        build_opener.return_value.open.side_effect = self.authorize_redirect(
            "uk.co.davidlloyd.mobile-app:/login?code=secret&state=wrong"
        )

        with self.assertRaisesRegex(RuntimeError, "Autorisierung"):
            app.authorize_code(self.flow, "one-time-session")

    @mock.patch("app.urllib.request.build_opener")
    def test_authorize_code_rejects_non_callback_redirect(self, build_opener):
        build_opener.return_value.open.side_effect = self.authorize_redirect(
            "https://example.invalid/callback?code=secret&state=expected-state"
        )

        with self.assertRaisesRegex(RuntimeError, "Autorisierung"):
            app.authorize_code(self.flow, "one-time-session")

    @mock.patch("app.urllib.request.build_opener")
    def test_authorize_code_hides_non_redirect_provider_errors(self, build_opener):
        build_opener.return_value.open.side_effect = urllib.error.HTTPError(
            app.AUTHORIZE_URL,
            400,
            "Bad Request",
            Message(),
            None,
        )

        with self.assertRaisesRegex(RuntimeError, "Autorisierung"):
            app.authorize_code(self.flow, "one-time-session")

    @mock.patch("app.urllib.request.build_opener")
    def test_authorize_code_hides_malformed_redirect_errors(self, build_opener):
        build_opener.return_value.open.side_effect = ValueError("bad redirect")

        with self.assertRaisesRegex(RuntimeError, "Autorisierung"):
            app.authorize_code(self.flow, "one-time-session")

    def test_jwt_hints_only_exposes_allowlisted_claims(self):
        payload = app.base64.urlsafe_b64encode(
            json.dumps({"exp": 123, "contactId": "abc", "groups": ["admin"]}).encode()
        ).rstrip(b"=").decode()
        hints = app.jwt_hints(f"x.{payload}.y")
        self.assertEqual(hints, {"exp": 123, "contactId": "abc"})


if __name__ == "__main__":
    unittest.main()
