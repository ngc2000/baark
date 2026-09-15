# Copyright (c) 2026 doabell.
"""Exercise the opt-in live runner with synthetic configuration and mock HTTP."""

from __future__ import annotations

import asyncio
import io
import json
import os
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import TYPE_CHECKING, cast, override
from unittest.mock import patch

import httpx2

from baark import AsyncBaark, Baark, EncryptedPayload, Encryption

if TYPE_CHECKING:
    from collections.abc import Callable


class E2ERunnerTests(unittest.TestCase):
    """Check actual wire payloads and CLI guards without sending notifications."""

    @override
    def setUp(self) -> None:
        """Load the standalone runner without executing its main guard."""
        script = Path(__file__).resolve().parents[1] / "scripts" / "e2e.py"
        self.main = cast(
            "Callable[[list[str]], None]", runpy.run_path(str(script))["main"]
        )
        self.requests: list[dict[str, str]] = []
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.response = httpx2.Response(200, json={"code": 200, "message": "success"})

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """Record mock HTTP requests and return a controlled response."""
        self.requests.append(json.loads(request.content))
        return httpx2.Response(
            self.response.status_code,
            headers=self.response.headers,
            content=self.response.content,
        )

    def run_cli(
        self,
        args: list[str],
        *,
        encryption: Encryption | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        """Run against fresh clients with mock transports and no real environment."""
        async_http = httpx2.AsyncClient(
            transport=httpx2.MockTransport(self.handle), trust_env=False
        )
        self.addCleanup(lambda: asyncio.run(async_http.aclose()))
        with (
            httpx2.Client(
                transport=httpx2.MockTransport(self.handle), trust_env=False
            ) as http,
            patch.dict(
                os.environ, {"BAARK_DEVICE_KEY": "TEST_KEY", **(env or {})}, clear=True
            ),
            patch.object(
                Baark,
                "from_env",
                return_value=Baark("TEST_KEY", http_client=http, encryption=encryption),
            ),
            patch.object(
                AsyncBaark,
                "from_env",
                return_value=AsyncBaark(
                    "TEST_KEY",
                    http_client=async_http,
                    encryption=encryption,
                ),
            ),
            redirect_stdout(self.stdout),
            redirect_stderr(self.stderr),
        ):
            self.main(args)

    def test_encrypted_visual_cases_with_both_clients(self) -> None:
        """Decrypt both clients' real requests and check the visual feature fields."""
        encryption = Encryption("K" * 32)
        self.run_cli(
            ["--case", "all"],
            encryption=encryption,
            env={
                "BAARK_E2E_LOGO_URL": "https://example.com/custom-logo.png",
                "BAARK_E2E_IMAGE_URL": "https://example.com/custom-image.png",
            },
        )
        self.assertEqual(len(self.requests), 18)
        self.assertEqual(len({p["id"] for p in self.requests}), 18)
        decoded = {
            payload["id"]: json.loads(
                encryption.decrypt(
                    EncryptedPayload(payload["ciphertext"], payload["iv"])
                )
            )
            for payload in self.requests
        }
        for interface in ("sync", "async"):
            prefix = f"baark-e2e-{interface}"
            with self.subTest(client=interface):
                self.assertIn("Sent through", decoded[prefix]["body"])
                self.assertEqual(
                    decoded[f"{prefix}-logo"]["icon"],
                    "https://example.com/custom-logo.png",
                )
                self.assertEqual(
                    decoded[f"{prefix}-image"]["image"],
                    "https://example.com/custom-image.png",
                )
                self.assertIn(
                    "**Bold text**", decoded[f"{prefix}-markdown"]["markdown"]
                )
                self.assertEqual(decoded[f"{prefix}-copy"]["copy"], "BAARK-E2E-COPY")
                self.assertEqual(decoded[f"{prefix}-copy"]["autoCopy"], "1")
                self.assertEqual(decoded[f"{prefix}-sound"]["sound"], "bell")
                self.assertEqual(decoded[f"{prefix}-history"]["isArchive"], "1")
                self.assertEqual(decoded[f"{prefix}-ephemeral"]["isArchive"], "0")
        self.assertTrue(all(p["group"] == "baark-e2e" for p in decoded.values()))
        self.assertNotIn("custom-logo.png", self.stdout.getvalue())

    def test_selection_updates_and_deletion_keep_ids(self) -> None:
        """Duplicates send once; updates retain media; deletes use identical IDs."""
        groups: list[list[dict[str, str]]] = []
        for action in ("send", "update", "delete"):
            self.requests = []
            self.run_cli(
                ["--case", "logo", "image", "--case", "logo", "--action", action]
            )
            self.assertEqual(len(self.requests), 4)
            groups.append(self.requests)
        self.assertEqual([p["id"] for p in groups[0]], [p["id"] for p in groups[1]])
        self.assertEqual([p["id"] for p in groups[0]], [p["id"] for p in groups[2]])
        self.assertTrue(all("Updated through" in p["body"] for p in groups[1]))
        self.assertEqual(groups[0][0]["icon"], groups[1][0]["icon"])
        self.assertEqual(groups[0][1]["image"], groups[1][1]["image"])
        for payload in groups[2]:
            self.assertEqual(set(payload), {"device_key", "id", "delete", "body"})
            self.assertEqual(payload["delete"], "1")
            self.assertEqual(payload["body"], "")

    def test_invalid_configuration_sends_nothing(self) -> None:
        """Validate the complete selection before sending, without echoing URLs."""
        invalid_args = [
            ["--case", "basic", "logo", "--logo-url", "file:///private/image.png"],
            ["--case", "image", "--image-url", "https://[bad-host/private"],
        ]
        for args in invalid_args:
            with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                self.run_cli(args)
            self.assertEqual(caught.exception.code, 2)
        with self.assertRaises(SystemExit) as caught:
            self.run_cli([], env={"BAARK_DEVICE_KEY": "YOUR_DEVICE_KEY"})
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.requests, [])
        self.assertNotIn("private", self.stderr.getvalue())

    def test_list_cases_needs_no_credentials_or_clients(self) -> None:
        """Listing checks can never perform network I/O or construct a client."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(Baark, "from_env") as sync,
            patch.object(AsyncBaark, "from_env") as asynchronous,
            redirect_stdout(self.stdout),
        ):
            self.main(["--list-cases"])
        sync.assert_not_called()
        asynchronous.assert_not_called()
        self.assertIn("logo:", self.stdout.getvalue())
        self.assertIn("image:", self.stdout.getvalue())

    def test_api_failure_stops_selection_and_hides_raw_details(self) -> None:
        """A server failure stops later cases and keeps raw messages opt-in."""
        self.response = httpx2.Response(
            500, json={"code": 500, "message": "private-server-detail"}
        )
        with self.assertRaises(SystemExit) as caught:
            self.run_cli(["--case", "all"])
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn("private-server-detail", self.stderr.getvalue())
        self.assertNotIn("Server accepted", self.stdout.getvalue())
        with self.assertRaises(SystemExit):
            self.run_cli(["--client", "sync", "--show-server-message"])
        self.assertIn("private-server-detail", self.stderr.getvalue())
