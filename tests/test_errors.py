# Copyright (c) 2026 doabell.
"""APNs errors must remain actionable despite Bark's outer HTTP 500 wrapper."""

import unittest

from baark import APIError, APNSReason, Delivery


class APNSErrorTests(unittest.TestCase):
    """Recognize upstream and deployed-server error formats without leaking text."""

    def test_wrapped_apns_rejections(self) -> None:
        """Recognize exact APNs names while preserving the reported HTTP status."""
        for prefix in (
            "push failed: ",
            "APNS push failed: ",
            "push failed: APNS push failed: ",
        ):
            for reason in (
                APNSReason.BAD_DEVICE_TOKEN,
                APNSReason.INVALID_PROVIDER_TOKEN,
                APNSReason.UNREGISTERED,
                APNSReason.TOO_MANY_REQUESTS,
                APNSReason.SERVICE_UNAVAILABLE,
            ):
                with self.subTest(prefix=prefix, reason=reason):
                    message = f"{prefix}{reason}"
                    error = APIError(status_code=500, code=500, server_message=message)
                    self.assertEqual(error.status_code, 500)
                    self.assertEqual(error.code, 500)
                    self.assertEqual(error.server_message, message)
                    self.assertEqual(error.apns_reason, reason)
                    self.assertIn(f"APNs reason: {reason}", str(error))

    def test_free_form_messages_are_not_classified_or_printed(self) -> None:
        """Partial matches and unknown reasons stay available only by inspection."""
        for message in (
            None,
            "",
            "Forbidden",
            "BadDeviceToken",
            "push failed: Post https://host/SECRET_TOKEN: connection reset",
            "push failed: BadDeviceToken SECRET_TOKEN",
            "SECRET_TOKEN BadDeviceToken",
            "push failed: FutureAPNsReason",
        ):
            with self.subTest(message=message):
                error = APIError(status_code=500, server_message=message)
                self.assertIsNone(error.apns_reason)
                self.assertEqual(error.server_message, message)
                self.assertEqual(
                    str(error), "Bark request failed (HTTP 500, code None)."
                )

    def test_delivery_reason(self) -> None:
        """Batch deliveries distinguish accepted, APNs-rejected, and other errors."""
        for code, message, reason in (
            (200, "BadDeviceToken", None),
            (
                500,
                "push failed: APNS push failed: BadDeviceToken",
                APNSReason.BAD_DEVICE_TOKEN,
            ),
            (500, "push failed: connection reset", None),
        ):
            with self.subTest(code=code, message=message):
                delivery = Delivery("PRIVATE_KEY", code, message)
                self.assertEqual(delivery.apns_reason, reason)
                self.assertNotIn("PRIVATE_KEY", repr(delivery))
