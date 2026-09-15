# Copyright (c) 2026 doabell.
"""Offline HTTP integration tests with real httpx2 clients and mock transports."""

from __future__ import annotations

import json
import unittest
from types import MappingProxyType
from typing import cast, override
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx2

from baark import (
    APIError,
    APNSReason,
    Baark,
    BatchError,
    EncryptedPayload,
    Encryption,
    Endpoint,
    Message,
    ProtocolError,
    TransportError,
    ValidationError,
    send,
)


class ClientTests(unittest.TestCase):
    """Check requests and responses without contacting a Bark server."""

    @override
    def setUp(self) -> None:
        """Create an HTTP pool whose entire network is an in-memory handler."""
        self.requests: list[httpx2.Request] = []
        self.response = httpx2.Response(200, json={"code": 200, "message": "success"})
        self.http = httpx2.Client(transport=httpx2.MockTransport(self.handle))
        self.addCleanup(self.http.close)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """Record the fully encoded request and return a configured response.

        Args:
            request: Prepared HTTP request.

        Returns:
            The current mock response.
        """
        self.requests.append(request)
        return self.response

    def payload(self) -> dict[str, object]:
        """Decode the most recently sent JSON request."""
        return cast("dict[str, object]", json.loads(self.requests[-1].content))

    def test_json_request_and_unicode(self) -> None:
        """Use POST /push and preserve Unicode and URL-like notification text."""
        body = "你好 👋 / a+b?x=1#fragment\nnext line"
        with Baark("KEY", http_client=self.http) as client:
            result = client.send(body, title="Hello", url="myapp://item/1")
        request = self.requests[-1]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://api.day.app/push")
        self.assertEqual(
            self.payload(),
            {
                "device_key": "KEY",
                "body": body,
                "title": "Hello",
                "url": "myapp://item/1",
            },
        )
        self.assertIn("application/json", request.headers["content-type"])
        self.assertTrue(result.ok)
        self.assertFalse(self.http.is_closed)

    def test_default_merging_and_clearing(self) -> None:
        """Calls can override aliases and explicitly remove inherited defaults."""
        with Baark(
            "KEY", http_client=self.http, group="default", icon="old", archive=True
        ) as client:
            client.send(
                Message("hello", title="template"),
                group=None,
                logo="new",
                archive=False,
            )
            first = self.payload()
            client.send("second")
            second = self.payload()
        self.assertNotIn("group", first)
        self.assertEqual(first["title"], "template")
        self.assertEqual(first["icon"], "new")
        self.assertEqual(first["isArchive"], "0")
        self.assertEqual(second["group"], "default")
        self.assertEqual(second["icon"], "old")
        self.assertEqual(second["isArchive"], "1")
        self.assertNotIn("title", second)

    def test_custom_server_prefix_and_device_url(self) -> None:
        """A copied URL and explicit server prefix resolve to the same API."""
        with Baark("https://bark.example/prefix/KEY/", http_client=self.http) as client:
            client.send("hello")
            self.assertEqual(client.server_url, "https://bark.example/prefix")
            self.assertEqual(client.mcp_url, "https://bark.example/prefix/mcp/KEY")
        self.assertEqual(str(self.requests[-1].url), "https://bark.example/prefix/push")
        with Baark(
            "KEY", server_url="https://bark.example/prefix/", http_client=self.http
        ) as client:
            client.send("hello")
        self.assertEqual(str(self.requests[-1].url), "https://bark.example/prefix/push")

    def test_single_recipient_override(self) -> None:
        """A per-call key override never changes the configured recipient."""
        with Baark("DEFAULT", http_client=self.http) as client:
            client.send("one", device_key="OTHER")
            self.assertEqual(self.payload()["device_key"], "OTHER")
            client.send("two")
            self.assertEqual(self.payload()["device_key"], "DEFAULT")

    def test_legacy_endpoints(self) -> None:
        """JSON, form, and GET device endpoints encode the same options."""
        body = "a/b + c?你好#fragment"
        with Baark("KEY", http_client=self.http) as client:
            client.send(body, endpoint="device", archive=False)
            self.assertEqual(str(self.requests[-1].url), "https://api.day.app/KEY")
            self.assertEqual(self.payload(), {"body": body, "isArchive": "0"})
            client.send(body, endpoint="form", archive=False)
            self.assertEqual(self.requests[-1].method, "POST")
            self.assertEqual(
                parse_qs(self.requests[-1].content.decode()),
                {
                    "body": [body],
                    "isArchive": ["0"],
                },
            )
            client.send(body, endpoint="get", archive=False)
            self.assertEqual(self.requests[-1].method, "GET")
            self.assertEqual(self.requests[-1].url.params["body"], body)
            self.assertEqual(self.requests[-1].url.params["isArchive"], "0")

    def test_url_building_has_no_network_side_effect(self) -> None:
        """Webhook URLs are safely encoded and generated without sending."""
        with Baark("KEY", http_client=self.http) as client:
            url = client.build_url("a/b + ?#\n你好", title="title/with/slashes")
        self.assertEqual(len(self.requests), 0)
        parsed = urlsplit(url)
        self.assertEqual(parsed.path, "/KEY")
        self.assertEqual(parse_qs(parsed.query)["body"], ["a/b + ?#\n你好"])

    def test_get_preserves_payload_with_http_query_defaults(self) -> None:
        """Client query defaults must not replace clear or encrypted GET fields."""
        self.http.params = {"token": "example", "body": "old"}
        for encryption in (None, Encryption("K" * 32)):
            with (
                self.subTest(encrypted=encryption is not None),
                Baark("KEY", http_client=self.http, encryption=encryption) as client,
            ):
                client.send("hello / 世界", title="new", endpoint="get")
            params = self.requests[-1].url.params
            self.assertEqual(params["token"], "example")
            if encryption is None:
                self.assertEqual(params["body"], "hello / 世界")
                self.assertEqual(params["title"], "new")
            else:
                plaintext = encryption.decrypt(
                    EncryptedPayload(params["ciphertext"], params["iv"])
                )
                self.assertEqual(
                    json.loads(plaintext), {"body": "hello / 世界", "title": "new"}
                )

    def test_readonly_extension_defaults_and_overrides(self) -> None:
        """Read-only mappings work throughout default and per-call merging."""
        with Baark(
            "KEY", http_client=self.http, extra=MappingProxyType({"future": [1]})
        ) as client:
            client.send("defaults")
            self.assertEqual(self.payload()["future"], [1])
            client.send("override", extra=MappingProxyType({"future": [2]}))
        self.assertEqual(self.payload()["future"], [2])

    def test_http_query_defaults_cannot_change_notifications(self) -> None:
        """Bark query precedence must not redirect, delete, or replace SDK sends."""
        self.http.params = {
            "token": ["first", "second"],
            "device_key": "OTHER",
            "device_keys": "OTHER",
            "Delete": "1",
            "ID": "wrong",
            "body": "old",
            "ciphertext": "invalid",
            "iv": "invalid",
            "FUTURE": "old",
        }
        original = self.http.params
        for encryption in (None, Encryption("K" * 32)):
            for endpoint in Endpoint:
                with (
                    self.subTest(endpoint=endpoint, encrypted=encryption is not None),
                    Baark(
                        "KEY", http_client=self.http, encryption=encryption
                    ) as client,
                ):
                    client.send(
                        "new", id="job", endpoint=endpoint, extra={"future": "new"}
                    )
                query = self.requests[-1].url.params
                self.assertEqual(query.get_list("token"), ["first", "second"])
                for name in ("device_key", "device_keys", "Delete", "ID", "FUTURE"):
                    self.assertNotIn(name, query)
                if endpoint == Endpoint.GET:
                    self.assertEqual(query["id"], "job")
                    if encryption is None:
                        self.assertEqual(query["body"], "new")
                        self.assertEqual(query["future"], "new")
                    else:
                        self.assertNotIn("body", query)
                        self.assertEqual(
                            json.loads(
                                encryption.decrypt(
                                    EncryptedPayload(query["ciphertext"], query["iv"])
                                )
                            )["body"],
                            "new",
                        )
                else:
                    self.assertEqual(set(query), {"token"})
        self.assertEqual(self.http.params, original)

    def test_query_defaults_cannot_override_flattened_extensions(self) -> None:
        """Nested extension fields also take precedence over HTTP query defaults."""
        self.http.params = {"FLAG": "old", "trace": "preserved"}
        with Baark("KEY", http_client=self.http) as client:
            client.send("new", extra={"future": {"flag": "new"}})
        self.assertEqual(dict(self.requests[-1].url.params), {"trace": "preserved"})
        self.assertEqual(self.payload()["future"], {"flag": "new"})

    def test_encryption_preserves_routing_and_hides_content(self) -> None:
        """Only ciphertext, IV, and server control/routing fields remain visible."""
        settings = Encryption("K" * 32)
        with Baark("KEY", http_client=self.http, encryption=settings) as client:
            client.send("private", title="secret", group="private group", id="stable")
            payload = self.payload()
            self.assertEqual(set(payload), {"device_key", "ciphertext", "iv", "id"})
            self.assertNotIn(b"private", self.requests[-1].content)
            plaintext = settings.decrypt(
                EncryptedPayload(
                    cast("str", payload["ciphertext"]), cast("str", payload["iv"])
                )
            )
            self.assertEqual(
                json.loads(plaintext),
                {
                    "body": "private",
                    "title": "secret",
                    "group": "private group",
                    "id": "stable",
                },
            )
            client.delete("stable")
            self.assertEqual(self.payload()["id"], "stable")
            self.assertEqual(self.payload()["delete"], "1")

    def test_encrypted_url(self) -> None:
        """URL generation uses encryption and does not expose the plaintext."""
        with Baark(
            "KEY", http_client=self.http, encryption=Encryption("K" * 16)
        ) as client:
            query = parse_qs(urlsplit(client.build_url("private")).query)
        self.assertEqual(set(query), {"ciphertext", "iv"})
        self.assertEqual(len(self.requests), 0)

    def test_double_encryption_is_rejected(self) -> None:
        """Pre-encrypted inputs cannot be silently encrypted again."""
        with (
            Baark(
                "KEY", http_client=self.http, encryption=Encryption("K" * 32)
            ) as client,
            self.assertRaises(ValidationError),
        ):
            client.send(ciphertext="YQ==", iv="123456789012")
        self.assertEqual(len(self.requests), 0)

    def test_batch_success(self) -> None:
        """A keyless client can send a batch and gets typed per-device results."""
        self.response = httpx2.Response(
            200,
            json={
                "code": 200,
                "message": "success",
                "timestamp": 123,
                "data": [
                    {"device_key": "A", "code": 200},
                    {"device_key": "B", "code": 200},
                ],
            },
        )
        with Baark(http_client=self.http) as client:
            result = client.send("hello", device_keys=["A", "B"])
        self.assertEqual(self.payload(), {"body": "hello", "device_keys": ["A", "B"]})
        self.assertEqual(
            tuple(item.device_key for item in result.deliveries), ("A", "B")
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.timestamp, 123)

    def test_partial_batch_failure_is_explicit(self) -> None:
        """HTTP 200 must not hide a failed recipient, and successes remain visible."""
        self.response = httpx2.Response(
            200,
            json={
                "code": 200,
                "message": "success",
                "data": [
                    {"device_key": "A", "code": 200},
                    {"device_key": "B", "code": 400, "message": "invalid device"},
                ],
            },
        )
        with (
            Baark(
                "DEFAULT", http_client=self.http, encryption=Encryption("K" * 32)
            ) as client,
            self.assertRaises(BatchError) as caught,
        ):
            client.send("private", device_keys=["A", "B"])
        self.assertFalse(caught.exception.response.ok)
        self.assertEqual(caught.exception.response.failures[0].device_key, "B")
        self.assertTrue(caught.exception.response.deliveries[0].ok)
        self.assertNotIn("device_key", self.payload())
        self.assertEqual(self.payload()["device_keys"], ["A", "B"])

    def test_malformed_batch_results(self) -> None:
        """Missing, duplicate, and unexpected recipient results must fail."""
        for data in (
            None,
            [],
            ["bad"],
            [{"device_key": "B", "code": 200}],
            [{"device_key": "A", "code": True}],
            [{"device_key": "A", "code": 200}] * 2,
        ):
            self.response = httpx2.Response(
                200, json={"code": 200, "message": "ok", "data": data}
            )
            with (
                self.subTest(data=data),
                Baark(http_client=self.http) as client,
                self.assertRaises(ProtocolError),
            ):
                client.send("test", device_keys=["A"])

    def test_malformed_success_responses(self) -> None:
        """HTML, wrong JSON shapes, and missing statuses must fail explicitly."""
        responses = [
            httpx2.Response(200, text="<html>proxy login</html>"),
            httpx2.Response(200, json=[]),
            httpx2.Response(200, json={}),
            httpx2.Response(200, json={"code": True, "message": "ok"}),
            httpx2.Response(
                200, json={"code": 200, "message": "ok", "timestamp": "bad"}
            ),
            httpx2.Response(200, json={"code": 200}),
        ]
        for response in responses:
            self.response = response
            with (
                self.subTest(body=response.text),
                Baark("KEY", http_client=self.http) as client,
                self.assertRaises(ProtocolError),
            ):
                client.send("test")

    def test_http_and_application_errors(self) -> None:
        """Expose status attributes without echoing server data in exception text."""
        cases = (
            (httpx2.Response(503, text="unavailable"), 503, None),
            (
                httpx2.Response(200, json={"code": 400, "message": "KEY rejected"}),
                200,
                400,
            ),
            (httpx2.Response(401, json={"code": 401, "message": "no auth"}), 401, 401),
        )
        for response, status, code in cases:
            self.response = response
            with (
                self.subTest(status=status),
                Baark("KEY", http_client=self.http) as client,
                self.assertRaises(APIError) as caught,
            ):
                client.send("secret")
            self.assertEqual(caught.exception.status_code, status)
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("KEY", str(caught.exception))

    def test_redirect_is_not_followed(self) -> None:
        """Do not forward a notification to an unrequested redirect destination."""
        self.response = httpx2.Response(
            307, headers={"Location": "https://other.example/push"}
        )
        with (
            Baark("KEY", http_client=self.http) as client,
            self.assertRaises(APIError),
        ):
            client.send("secret")
        self.assertEqual(len(self.requests), 1)

    def test_apns_failure_is_reported_without_retry(self) -> None:
        """A real server envelope exposes BadDeviceToken without raw debug output."""
        self.response = httpx2.Response(
            500,
            json={
                "code": 500,
                "message": "push failed: APNS push failed: BadDeviceToken",
            },
        )
        with (
            Baark("KEY", http_client=self.http) as client,
            self.assertRaises(APIError) as caught,
        ):
            client.send("test")
        self.assertEqual(caught.exception.apns_reason, APNSReason.BAD_DEVICE_TOKEN)
        self.assertIn("BadDeviceToken", str(caught.exception))
        self.assertEqual(len(self.requests), 1)

    def test_transport_error_is_not_retried_or_leaked(self) -> None:
        """An uncertain delivery must not be duplicated by implicit retries."""
        with (
            patch.object(
                self.http, "send", side_effect=httpx2.ReadTimeout("secret URL KEY")
            ) as request,
            Baark("KEY", http_client=self.http) as client,
            self.assertRaises(TransportError) as caught,
        ):
            client.send("secret")
        self.assertEqual(request.call_count, 1)
        self.assertNotIn("KEY", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_update_and_delete(self) -> None:
        """Use stable IDs and explicit deletion flags without needing dummy text."""
        with Baark("KEY", http_client=self.http) as client:
            client.update("job", "finished")
            self.assertEqual(
                self.payload(),
                {
                    "body": "finished",
                    "id": "job",
                    "delete": "0",
                    "device_key": "KEY",
                },
            )
            client.delete("job")
            self.assertEqual(self.payload()["delete"], "1")
            with self.assertRaises(ValidationError):
                client.update("job", id="other")
            with self.assertRaises(ValidationError):
                client.update("job", delete=True)

    def test_update_requires_a_notification_id(self) -> None:
        """A missing ID must not silently send a new notification."""
        with Baark("KEY", http_client=self.http) as client:
            for notification_id in (None, "", 123):
                with (
                    self.subTest(notification_id=notification_id),
                    self.assertRaises(ValidationError),
                ):
                    client.update(cast("str", notification_id), "new")
        self.assertEqual(self.requests, [])

    def test_client_lifecycle(self) -> None:
        """Closing the wrapper prevents reuse and leaves a borrowed HTTP client open."""
        client = Baark("KEY", http_client=self.http)
        client.close()
        client.close()
        self.assertFalse(self.http.is_closed)
        with self.assertRaises(TransportError):
            client.send("test")

    def test_closed_borrowed_pool(self) -> None:
        """A caller-closed HTTP pool produces the documented SDK error."""
        client = Baark("KEY", http_client=self.http)
        self.addCleanup(client.close)
        self.http.close()
        with self.assertRaises(TransportError):
            client.send("test")
        with self.assertRaises(TransportError), client:
            self.fail("A closed pool must not enter a client context.")
        self.assertEqual(self.requests, [])

    def test_one_shot_closes_owned_pool(self) -> None:
        """The convenience function releases its connection pool after sending."""
        with patch("baark.client.httpx2.Client", return_value=self.http):
            response = send("hello", device_key="KEY")
        self.assertTrue(response.ok)
        self.assertTrue(self.http.is_closed)

    def test_environment_is_explicit(self) -> None:
        """Environment settings are loaded only when from_env is requested."""
        with patch.dict(
            "os.environ",
            {
                "BAARK_DEVICE_KEY": "ENV_KEY",
                "BAARK_SERVER_URL": "https://custom.example",
            },
            clear=True,
        ):
            with (
                Baark(http_client=self.http) as client,
                self.assertRaises(ValidationError),
            ):
                client.send("no implicit key")
            with (
                patch("baark.client.httpx2.Client", return_value=self.http),
                Baark.from_env(group="env") as client,
            ):
                client.send("hello")
        self.assertEqual(self.payload()["device_key"], "ENV_KEY")
        self.assertEqual(str(self.requests[-1].url), "https://custom.example/push")

    def test_validation_happens_before_network(self) -> None:
        """Reject ambiguous recipients and unsupported formats locally."""
        with Baark("KEY", http_client=self.http) as client:
            with self.assertRaises(ValidationError):
                client.send("test", device_key="A", device_keys=["B"])
            with self.assertRaises(ValidationError):
                client.send("test", device_keys=[])
            with self.assertRaises(ValidationError):
                client.send("test", device_keys="A")
            with self.assertRaises(ValidationError):
                client.send("test", device_keys=["A"], endpoint="get")
            with self.assertRaises(ValidationError):
                client.send("test", endpoint="form", extra={"future": {"x": 1}})
        self.assertEqual(len(self.requests), 0)

    def test_invalid_destinations(self) -> None:
        """Catch malformed URLs without accidentally treating them as device keys."""
        urls = (
            "https://api.day.app",
            "https://user:pass@example.org/KEY",
            "https://host/KEY?x=1",
            "https://host/KEY#fragment",
            "https://host:invalid/KEY",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValidationError):
                Baark(url, http_client=self.http)
        with self.assertRaises(ValidationError):
            Baark("KEY", server_url="ftp://example.org", http_client=self.http)
        with self.assertRaises(ValidationError):
            Baark("https://host/KEY", server_url="https://other", http_client=self.http)

    def test_invalid_client_settings(self) -> None:
        """Configuration errors fail before an HTTP client can be used."""
        with self.assertRaises(ValidationError):
            Baark(123, http_client=self.http)  # ty: ignore[invalid-argument-type]
        with self.assertRaises(ValidationError):
            Baark(server_url=123, http_client=self.http)  # ty: ignore[invalid-argument-type]
        with self.assertRaises(ValidationError):
            Baark(encryption="key", http_client=self.http)  # ty: ignore[invalid-argument-type]
        with self.assertRaises(ValidationError):
            Baark(http_client=cast("httpx2.Client", object()))
        with self.assertRaises(ValidationError):
            Baark(endpoint="unsupported", http_client=self.http)  # ty: ignore[invalid-argument-type]
        self.assertEqual(len(self.requests), 0)

    def test_invalid_device_keys(self) -> None:
        """Reject empty, ambiguous, and malformed URL segments without leaking them."""
        for key in ("", "has space", "\0", "a/b", "a\\b", "a?b", "a#b", ".", ".."):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                Baark(key, http_client=self.http)
        self.assertEqual(len(self.requests), 0)

    def test_environment_encryption_import(self) -> None:
        """Existing environment keys encrypt requests using the selected app mode."""
        cases = (
            ({"BAARK_ENCRYPTION_KEY": "K" * 32}, Encryption("K" * 32)),
            (
                {
                    "BAARK_ENCRYPTION_KEY": "K" * 16,
                    "BAARK_ENCRYPTION_MODE": "CBC",
                    "BAARK_ENCRYPTION_IV": "I" * 16,
                },
                Encryption("K" * 16, mode="CBC", iv="I" * 16),
            ),
        )
        for environment, settings in cases:
            with (
                self.subTest(mode=settings.mode),
                httpx2.Client(transport=httpx2.MockTransport(self.handle)) as http,
                patch("baark.client.httpx2.Client", return_value=http),
                patch.dict(
                    "os.environ", {"BAARK_DEVICE_KEY": "KEY", **environment}, clear=True
                ),
                Baark.from_env(group="env") as client,
            ):
                client.send("Existing key")
            payload = self.payload()
            plaintext = settings.decrypt(
                EncryptedPayload(
                    cast("str", payload["ciphertext"]), cast("str", payload["iv"])
                )
            )
            self.assertEqual(
                json.loads(plaintext), {"body": "Existing key", "group": "env"}
            )
            self.assertTrue(http.is_closed)

    def test_incomplete_environment_encryption(self) -> None:
        """Mode or IV alone must not silently disable requested encryption."""
        for environment in (
            {"BAARK_ENCRYPTION_MODE": "CBC"},
            {"BAARK_ENCRYPTION_IV": "I" * 16},
        ):
            with (
                self.subTest(environment=environment),
                patch.dict("os.environ", environment, clear=True),
                self.assertRaises(ValidationError),
            ):
                Baark.from_env()

    def test_client_repr_hides_credentials(self) -> None:
        """Accidental logging of the client should not reveal secret keys."""
        with Baark(
            "SECRET_KEY", http_client=self.http, encryption=Encryption("K" * 32)
        ) as client:
            self.assertNotIn("SECRET_KEY", repr(client))
            self.assertNotIn("K" * 32, repr(client))
