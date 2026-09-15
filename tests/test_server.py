# Copyright (c) 2026 doabell.
"""Registration, health, server information, and HTTP customization tests."""

from __future__ import annotations

import json
import unittest
from typing import override

import httpx2

from baark import APIError, Baark, ProtocolError, ValidationError


class ServerTests(unittest.TestCase):
    """Exercise the complete REST utility surface with mocked HTTP."""

    @override
    def setUp(self) -> None:
        """Create a recording mock server."""
        self.requests: list[httpx2.Request] = []
        self.response = httpx2.Response(200, text="ok")
        self.http = httpx2.Client(transport=httpx2.MockTransport(self.handle))
        self.addCleanup(self.http.close)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """Record a request and return the configured response.

        Args:
            request: HTTP request.

        Returns:
            The configured response.
        """
        self.requests.append(request)
        return self.response

    def test_keyless_utilities(self) -> None:
        """Server monitoring does not require a dummy device key."""
        with Baark(server_url="https://host/prefix", http_client=self.http) as client:
            self.assertEqual(client.root(), "ok")
            self.assertEqual(client.healthz(), "ok")
            self.assertEqual(client.mcp_url, "https://host/prefix/mcp")
            self.response = httpx2.Response(200, json={"code": 200, "message": "pong"})
            self.assertEqual(client.ping().message, "pong")
            self.response = httpx2.Response(
                200,
                json={
                    "version": "v2.2.5",
                    "build": "today",
                    "arch": "linux/amd64",
                    "commit": "abc",
                    "devices": 4,
                },
            )
            info = client.info()
        self.assertEqual(info.version, "v2.2.5")
        self.assertEqual(info.devices, 4)
        self.assertEqual(
            [request.url.path for request in self.requests],
            [
                "/prefix/",
                "/prefix/healthz",
                "/prefix/ping",
                "/prefix/info",
            ],
        )

    def test_registration_is_explicit(self) -> None:
        """Registering without a key must not overwrite the client's device mapping."""
        self.response = httpx2.Response(
            200,
            json={
                "code": 200,
                "message": "success",
                "data": {"device_key": "NEW_KEY", "device_token": "TOKEN"},
            },
        )
        with Baark("OLD_KEY", http_client=self.http) as client:
            result = client.register("TOKEN")
            self.assertEqual(
                json.loads(self.requests[-1].content), {"device_token": "TOKEN"}
            )
            self.assertEqual(result.device_key, "NEW_KEY")
            self.assertNotIn("TOKEN", repr(result))
            client.register("TOKEN", device_key="CUSTOM")
            self.assertEqual(
                json.loads(self.requests[-1].content),
                {
                    "device_token": "TOKEN",
                    "device_key": "CUSTOM",
                },
            )
            self.response = httpx2.Response(
                200, json={"code": 200, "message": "success"}
            )
            client.check_device()
        self.assertEqual(self.requests[-1].url.path, "/register/OLD_KEY")

    def test_unknown_device_is_an_api_error(self) -> None:
        """Registration checks raise rather than treating unknown keys as success."""
        self.response = httpx2.Response(
            400, json={"code": 400, "message": "unknown device"}
        )
        with Baark(http_client=self.http) as client, self.assertRaises(APIError):
            client.check_device("UNKNOWN")

    def test_invalid_registration_and_info(self) -> None:
        """Required response fields are validated for non-push endpoints too."""
        self.response = httpx2.Response(200, json={"code": 200, "message": "success"})
        with Baark(http_client=self.http) as client:
            with self.assertRaises(ProtocolError):
                client.register("TOKEN")
            with self.assertRaises(ProtocolError):
                client.info()
            with self.assertRaises(ValidationError):
                client.register("")

    def test_incomplete_registration_credentials(self) -> None:
        """A success envelope still needs nonempty device credentials."""
        for data in (
            {},
            {"device_key": "KEY"},
            {"device_key": "", "device_token": "TOKEN"},
            {"device_key": "KEY", "device_token": 123},
        ):
            self.response = httpx2.Response(
                200, json={"code": 200, "message": "success", "data": data}
            )
            with (
                self.subTest(data=data),
                Baark(http_client=self.http) as client,
                self.assertRaises(ProtocolError),
            ):
                client.register("TOKEN")

    def test_legacy_registration_credentials(self) -> None:
        """Older servers may return the device key under the legacy key name."""
        self.response = httpx2.Response(
            200,
            json={
                "code": 200,
                "message": "success",
                "data": {"key": "LEGACY_KEY", "device_token": "TOKEN"},
            },
        )
        with Baark(http_client=self.http) as client:
            result = client.register("TOKEN")
        self.assertEqual(result.device_key, "LEGACY_KEY")
        self.assertEqual(result.device_token, "TOKEN")

    def test_health_response_validation(self) -> None:
        """An arbitrary HTTP 200 page must not pass a health check."""
        with Baark(http_client=self.http) as client:
            self.response = httpx2.Response(200, text="login page")
            with self.assertRaises(ProtocolError):
                client.healthz()
            self.response = httpx2.Response(503, text="unavailable")
            with self.assertRaises(APIError):
                client.healthz()

    def test_injected_auth_and_timeout(self) -> None:
        """Preserve caller authentication and apply the SDK's explicit timeout."""
        self.response = httpx2.Response(200, json={"code": 200, "message": "pong"})
        self.http.auth = httpx2.BasicAuth("user", "example")
        with Baark(http_client=self.http, timeout=2.5) as client:
            client.ping()
        self.assertTrue(self.requests[-1].headers["Authorization"].startswith("Basic "))
        self.assertEqual(
            self.requests[-1].extensions["timeout"],
            {
                "connect": 2.5,
                "read": 2.5,
                "write": 2.5,
                "pool": 2.5,
            },
        )

    def test_ambiguous_auth_is_rejected(self) -> None:
        """Two separate authentication configurations must not silently conflict."""
        with self.assertRaises(ValidationError):
            Baark(http_client=self.http, auth=("user", "example"))
