# Copyright (c) 2026 doabell.
"""Async request parity, cancellation, and connection ownership tests."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import cast, override
from unittest.mock import patch

import httpx2

from baark import (
    APIError,
    APNSReason,
    AsyncBaark,
    Baark,
    BatchError,
    EncryptedPayload,
    Encryption,
    Message,
    ProtocolError,
    TransportError,
    ValidationError,
    async_send,
)


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    """Run actual async httpx2 requests through an in-memory transport."""

    @override
    async def asyncSetUp(self) -> None:
        """Create the shared mock transport and a caller-owned async pool."""
        self.requests: list[httpx2.Request] = []
        self.response = httpx2.Response(200, json={"code": 200, "message": "success"})
        self.http = httpx2.AsyncClient(transport=httpx2.MockTransport(self.handle))
        self.addAsyncCleanup(self.http.aclose)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """Record the fully encoded request.

        Args:
            request: Prepared HTTP request.

        Returns:
            The configured response.
        """
        self.requests.append(request)
        return httpx2.Response(
            self.response.status_code,
            headers=self.response.headers,
            content=self.response.content,
        )

    def payload(self) -> dict[str, object]:
        """Read the last JSON notification."""
        return cast("dict[str, object]", json.loads(self.requests[-1].content))

    async def test_async_send(self) -> None:
        """Async sends use the same readable options and default merging."""
        async with AsyncBaark("KEY", http_client=self.http, group="default") as client:
            result = await client.send(Message("hello", title="title"), archive=False)
        self.assertTrue(result.ok)
        self.assertEqual(
            self.payload(),
            {
                "body": "hello",
                "title": "title",
                "group": "default",
                "isArchive": "0",
                "device_key": "KEY",
            },
        )
        self.assertFalse(self.http.is_closed)

    async def test_get_preserves_payload_with_http_query_defaults(self) -> None:
        """Default query parameters must not discard encrypted async GET fields."""
        self.http.params = {"token": "example"}
        encryption = Encryption("K" * 32)
        async with AsyncBaark(
            "KEY", http_client=self.http, encryption=encryption
        ) as client:
            await client.send("private", endpoint="get")
        params = self.requests[-1].url.params
        self.assertEqual(params["token"], "example")
        self.assertEqual(
            json.loads(
                encryption.decrypt(EncryptedPayload(params["ciphertext"], params["iv"]))
            ),
            {"body": "private"},
        )

    async def test_sync_async_request_parity(self) -> None:
        """Identical messages must produce identical requests in both interfaces."""
        encryption = Encryption("K" * 32)
        sync_http = httpx2.Client(transport=httpx2.MockTransport(self.handle))
        with (
            sync_http,
            Baark(
                "https://host/prefix/KEY", http_client=sync_http, encryption=encryption
            ) as sync_client,
            patch("baark.crypto.secrets.choice", return_value="N"),
        ):
            sync_client.send("你好", id="job", volume=0, archive=False)
        async with AsyncBaark(
            "https://host/prefix/KEY", http_client=self.http, encryption=encryption
        ) as async_client:
            with patch("baark.crypto.secrets.choice", return_value="N"):
                await async_client.send("你好", id="job", volume=0, archive=False)
        first, second = self.requests
        self.assertEqual(first.url, second.url)
        self.assertEqual(first.content, second.content)
        self.assertEqual(first.method, second.method)

    async def test_update_and_delete(self) -> None:
        """Async update and delete preserve notification identity."""
        async with AsyncBaark("KEY", http_client=self.http) as client:
            await client.update("job", "finished")
            self.assertEqual(self.payload()["id"], "job")
            self.assertEqual(self.payload()["delete"], "0")
            await client.delete("job")
            self.assertEqual(self.payload()["id"], "job")
            self.assertEqual(self.payload()["delete"], "1")

    async def test_query_defaults_cannot_change_lifecycle_or_routing(self) -> None:
        """Async sends preserve explicit recipients and lifecycle controls."""
        self.http.params = {
            "token": "preserved",
            "device_keys": "OTHER",
            "delete": "1",
            "id": "wrong",
            "body": "old",
        }
        original = self.http.params
        async with AsyncBaark("KEY", http_client=self.http) as client:
            await client.send("new", id="job")
            self.assertNotIn("delete", self.payload())
            await client.update("job", "updated")
            self.assertEqual(self.payload()["delete"], "0")
            await client.delete("job")
            self.assertEqual(self.payload()["delete"], "1")
        for request in self.requests:
            self.assertEqual(dict(request.url.params), {"token": "preserved"})
            payload = json.loads(request.content)
            self.assertEqual(payload["device_key"], "KEY")
            self.assertEqual(payload["id"], "job")
            self.assertNotIn("device_keys", payload)
        self.assertEqual(self.http.params, original)

    async def test_update_requires_a_notification_id(self) -> None:
        """Async updates reject missing IDs before sending anything."""
        async with AsyncBaark("KEY", http_client=self.http) as client:
            for notification_id in (None, "", 123):
                with (
                    self.subTest(notification_id=notification_id),
                    self.assertRaises(ValidationError),
                ):
                    await client.update(cast("str", notification_id), "new")
        self.assertEqual(self.requests, [])

    async def test_async_batch_errors(self) -> None:
        """Partial batch delivery must also raise in the async interface."""
        self.response = httpx2.Response(
            200,
            json={
                "code": 200,
                "message": "success",
                "data": [
                    {"device_key": "A", "code": 200},
                    {"device_key": "B", "code": 400},
                ],
            },
        )
        async with AsyncBaark(http_client=self.http) as client:
            with self.assertRaises(BatchError) as caught:
                await client.send("batch", device_keys=["A", "B"])
        self.assertEqual(caught.exception.response.failures[0].device_key, "B")

    async def test_async_invalid_response(self) -> None:
        """A malformed HTTP 200 must not be treated as async success."""
        self.response = httpx2.Response(200, text="not JSON")
        async with AsyncBaark("KEY", http_client=self.http) as client:
            with self.assertRaises(ProtocolError):
                await client.send("test")

    async def test_async_apns_reason(self) -> None:
        """Async calls expose the underlying APNs rejection without retrying."""
        self.response = httpx2.Response(
            500,
            json={
                "code": 500,
                "message": "push failed: APNS push failed: BadDeviceToken",
            },
        )
        async with AsyncBaark("KEY", http_client=self.http) as client:
            with self.assertRaises(APIError) as caught:
                await client.send("test")
        self.assertEqual(caught.exception.apns_reason, APNSReason.BAD_DEVICE_TOKEN)
        self.assertEqual(len(self.requests), 1)

    async def test_async_utilities_and_registration(self) -> None:
        """All utility endpoints are available on the async client."""
        async with AsyncBaark(
            "KEY", server_url="https://host/prefix", http_client=self.http
        ) as client:
            self.response = httpx2.Response(200, json={"code": 200, "message": "pong"})
            self.assertEqual((await client.ping()).message, "pong")
            self.response = httpx2.Response(200, text="ok")
            self.assertEqual(await client.healthz(), "ok")
            self.assertEqual(await client.root(), "ok")
            self.response = httpx2.Response(
                200,
                json={
                    "version": "v2",
                    "build": "today",
                    "arch": "linux/arm64",
                    "commit": "abc",
                    "devices": 2,
                },
            )
            self.assertEqual((await client.info()).devices, 2)
            self.response = httpx2.Response(
                200,
                json={
                    "code": 200,
                    "message": "success",
                    "data": {"device_key": "NEW", "device_token": "TOKEN"},
                },
            )
            self.assertEqual((await client.register("TOKEN")).device_key, "NEW")
            self.assertEqual(self.payload(), {"device_token": "TOKEN"})
            self.response = httpx2.Response(
                200, json={"code": 200, "message": "success"}
            )
            self.assertTrue((await client.check_device()).ok)
        self.assertEqual(
            [request.url.path for request in self.requests],
            [
                "/prefix/ping",
                "/prefix/healthz",
                "/prefix/",
                "/prefix/info",
                "/prefix/register",
                "/prefix/register/KEY",
            ],
        )

    async def test_async_close_ownership(self) -> None:
        """Closing the wrapper blocks further sends without closing a borrowed pool."""
        client = AsyncBaark("KEY", http_client=self.http)
        await client.aclose()
        await client.aclose()
        self.assertFalse(self.http.is_closed)
        with self.assertRaises(TransportError):
            await client.send("test")

    async def test_closed_borrowed_pool(self) -> None:
        """Closing an injected pool still produces the documented SDK error."""
        client = AsyncBaark("KEY", http_client=self.http)
        self.addAsyncCleanup(client.aclose)
        await self.http.aclose()
        with self.assertRaises(TransportError):
            await client.send("test")
        with self.assertRaises(TransportError):
            async with client:
                self.fail("A closed pool must not enter a client context.")
        self.assertEqual(self.requests, [])

    async def test_invalid_async_client_settings(self) -> None:
        """Reject ambiguous authentication and incompatible injected pools."""
        with self.assertRaises(ValidationError):
            AsyncBaark(http_client=self.http, auth=("user", "example"))
        with self.assertRaises(ValidationError):
            AsyncBaark(http_client=cast("httpx2.AsyncClient", object()))
        async with AsyncBaark("KEY", http_client=self.http) as client:
            with self.assertRaises(ValidationError):
                await client.update("job", delete=True)
        self.assertEqual(len(self.requests), 0)

    async def test_one_shot_closes_owned_pool(self) -> None:
        """The async convenience helper closes its own pool."""
        with patch("baark.client.httpx2.AsyncClient", return_value=self.http):
            self.assertTrue((await async_send("hello", device_key="KEY")).ok)
        self.assertTrue(self.http.is_closed)

    async def test_cancellation_propagates(self) -> None:
        """Caller cancellation must not become a generic SDK error or a retry."""
        started = asyncio.Event()
        release = asyncio.Event()

        async def pending(request: httpx2.Request) -> httpx2.Response:
            self.requests.append(request)
            started.set()
            await release.wait()
            return self.response

        async with (
            httpx2.AsyncClient(transport=httpx2.MockTransport(pending)) as http,
            AsyncBaark("KEY", http_client=http) as client,
        ):
            task = asyncio.create_task(client.send("wait"))
            await asyncio.wait_for(started.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(len(self.requests), 1)

    async def test_async_network_failure(self) -> None:
        """Transport failures are sanitized and surfaced once."""
        with patch.object(
            self.http, "send", side_effect=httpx2.ConnectError("SECRET_KEY")
        ) as request:
            async with AsyncBaark("KEY", http_client=self.http) as client:
                with self.assertRaises(TransportError) as caught:
                    await client.send("test")
        self.assertEqual(request.call_count, 1)
        self.assertNotIn("SECRET_KEY", str(caught.exception))
