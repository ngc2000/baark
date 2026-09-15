# Copyright (c) 2026 doabell.
"""Notification serialization and validation tests."""

import unittest
from types import MappingProxyType
from typing import cast

from baark import (
    Action,
    APIError,
    JSONValue,
    Level,
    Message,
    MessageOptions,
    Response,
    Sound,
    ValidationError,
)


class MessageTests(unittest.TestCase):
    """Check user-facing field handling independently of HTTP."""

    def test_complete_payload(self) -> None:
        """Serialize every field with exact names and preserve false/zero values."""
        message = Message(
            "body",
            title="title",
            subtitle="subtitle",
            markdown="**text**",
            level=Level.CRITICAL,
            volume=0,
            badge=0,
            call=False,
            auto_copy=True,
            copy="clipboard",
            sound=Sound.MAIL_SENT,
            logo="https://example.org/logo.png",
            image="https://example.org/image.png",
            group="group",
            archive=False,
            ttl=0,
            url="myapp://item/1",
            action=Action.ALERT,
            id="message-1",
            delete=False,
            extra={"future_field": "value"},
        )
        self.assertEqual(
            message.to_payload(),
            {
                "body": "body",
                "title": "title",
                "subtitle": "subtitle",
                "markdown": "**text**",
                "level": "critical",
                "volume": 0,
                "badge": 0,
                "call": "0",
                "autoCopy": "1",
                "copy": "clipboard",
                "sound": "mailsent",
                "icon": "https://example.org/logo.png",
                "image": "https://example.org/image.png",
                "group": "group",
                "isArchive": "0",
                "ttl": 0,
                "url": "myapp://item/1",
                "action": "alert",
                "id": "message-1",
                "delete": "0",
                "future_field": "value",
            },
        )

    def test_defaults_do_not_override_app_settings(self) -> None:
        """Unset flags must be absent rather than sending false implicitly."""
        self.assertEqual(Message("hello").to_payload(), {"body": "hello"})

    def test_markdown_and_deletion_do_not_require_dummy_body(self) -> None:
        """Markdown-only and silent deletion requests have natural constructors."""
        self.assertEqual(
            Message(markdown="# hello").to_payload()["markdown"], "# hello"
        )
        self.assertEqual(Message(id="old", delete=True).to_payload()["delete"], "1")

    def test_logo_alias_conflicts_are_reported(self) -> None:
        """The two spellings cannot silently overwrite each other."""
        self.assertEqual(Message(icon="a", logo="a").to_payload()["icon"], "a")
        with self.assertRaises(ValidationError):
            Message(icon="a", logo="b")

    def test_invalid_fields(self) -> None:
        """Reject incorrect types and inconsistent dependent options."""
        cases = [
            {"body": None},
            {"title": 3},
            {"volume": -1},
            {"volume": 11},
            {"volume": float("nan")},
            {"volume": True},
            {"badge": True},
            {"badge": 1.5},
            {"ttl": -1},
            {"ttl": False},
            {"call": "1"},
            {"auto_copy": 1},
            {"archive": "0"},
            {"level": "urgent"},
            {"action": "unknown"},
            {"delete": True},
            {"iv": "123456789012"},
            {"id": ""},
            {"id": "界" * 22},
            {"extra": []},
        ]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValidationError):
                Message(**cast("MessageOptions", options))

    def test_fractional_volume_and_signed_badge(self) -> None:
        """Accept values the app handles without overly restrictive validation."""
        self.assertEqual(Message(volume=2.5, badge=-1).to_payload()["volume"], 2.5)

    def test_extensions_cannot_override_routing(self) -> None:
        """Reject case-insensitive collisions with known wire fields."""
        for name in ("body", "DEVICE_KEY", "device_keys", "Ciphertext", "isArchive"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                Message(extra={name: "override"})

    def test_extension_json_values(self) -> None:
        """Allow JSON structures while rejecting objects and non-finite numbers."""
        message = Message(extra={"future": {"nested": [1, 2.5, True, None]}})
        payload = message.to_payload()
        self.assertEqual(payload["future"], {"nested": [1, 2.5, True, None]})
        for value in (object(), float("inf"), {1: "value"}):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Message(**cast("MessageOptions", {"extra": {"future": value}}))

    def test_flattened_extensions_cannot_override_known_fields(self) -> None:
        """Bark flattens object extensions into its notification control fields."""
        for name in ("delete", "group", "Ciphertext", "ID", "isArchive"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                Message(id="job", extra={"future": {name: "1"}})

    def test_readonly_extensions_are_supported(self) -> None:
        """The public Mapping type includes read-only mapping proxies."""
        message = Message(extra=MappingProxyType({"future": [1]}))
        self.assertEqual(message.to_payload()["future"], [1])

    def test_extensions_are_snapshotted_and_revalidated(self) -> None:
        """Caller mutations cannot change a message or bypass wire validation."""
        nested: list[JSONValue] = [1]
        extra: dict[str, JSONValue] = {"future": nested}
        message = Message(extra=extra)
        nested.append(2)
        extra["delete"] = "1"
        self.assertEqual(message.to_payload(), {"body": "", "future": [1]})
        cast("dict[str, JSONValue]", message.extra)["delete"] = "1"
        with self.assertRaises(ValidationError):
            message.to_payload()

    def test_payloads_are_independent_copies(self) -> None:
        """Mutating one serialization must not alter a reusable Message."""
        message = Message(extra={"future": [1, 2]})
        first = message.to_payload()
        first["future"] = [3]
        self.assertEqual(message.to_payload()["future"], [1, 2])

    def test_pre_encrypted_payload(self) -> None:
        """Pre-encrypted data is passed through without conversion."""
        self.assertEqual(
            Message(ciphertext="YQ==", iv="123456789012").to_payload(),
            {"body": "", "ciphertext": "YQ==", "iv": "123456789012"},
        )

    def test_response_status_error(self) -> None:
        """Manually constructed responses retain the public status contract."""
        result = Response(400, "private error detail", status_code=200)
        self.assertFalse(result.ok)
        with self.assertRaises(APIError) as caught:
            result.raise_for_status()
        self.assertEqual(caught.exception.status_code, 200)
        self.assertEqual(caught.exception.code, 400)
        self.assertEqual(caught.exception.server_message, "private error detail")
        self.assertNotIn("private", str(caught.exception))

    def test_response_http_status(self) -> None:
        """HTTP failures remain failures even with a successful Bark code."""
        for status in (199, 300, 503):
            with self.subTest(status=status):
                result = Response(200, "private detail", status_code=status)
                self.assertFalse(result.ok)
                with self.assertRaises(APIError) as caught:
                    result.raise_for_status()
                self.assertEqual(caught.exception.status_code, status)
        for status in (200, 204, 299):
            with self.subTest(status=status):
                result = Response(200, "ok", status_code=status)
                self.assertTrue(result.ok)
                result.raise_for_status()
