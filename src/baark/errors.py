# Copyright (c) 2026 doabell.
"""Errors raised by the baark SDK."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from baark.models import Response


class BaarkError(Exception):
    """Base class for SDK errors."""


class ValidationError(BaarkError, ValueError):
    """A notification or client setting is invalid."""


class EncryptionError(BaarkError, ValueError):
    """An encryption setting, ciphertext, or authentication tag is invalid."""


class TransportError(BaarkError):
    """An HTTP request failed before a usable response was received."""


class ProtocolError(BaarkError):
    """The server returned a response that does not follow the Bark API."""


class APNSReason(StrEnum):
    """APNs rejection reasons recognized by bark-server's apns2 dependency."""

    BAD_COLLAPSE_ID = "BadCollapseId"
    BAD_DEVICE_TOKEN = "BadDeviceToken"  # noqa: S105 - Public APNs reason.
    BAD_EXPIRATION_DATE = "BadExpirationDate"
    BAD_MESSAGE_ID = "BadMessageId"
    BAD_PRIORITY = "BadPriority"
    BAD_TOPIC = "BadTopic"
    DEVICE_TOKEN_NOT_FOR_TOPIC = "DeviceTokenNotForTopic"  # noqa: S105
    DUPLICATE_HEADERS = "DuplicateHeaders"
    IDLE_TIMEOUT = "IdleTimeout"
    INVALID_PUSH_TYPE = "InvalidPushType"
    MISSING_DEVICE_TOKEN = "MissingDeviceToken"  # noqa: S105
    MISSING_TOPIC = "MissingTopic"
    PAYLOAD_EMPTY = "PayloadEmpty"
    TOPIC_DISALLOWED = "TopicDisallowed"
    BAD_CERTIFICATE = "BadCertificate"
    BAD_CERTIFICATE_ENVIRONMENT = "BadCertificateEnvironment"
    EXPIRED_PROVIDER_TOKEN = "ExpiredProviderToken"  # noqa: S105
    FORBIDDEN = "Forbidden"
    INVALID_PROVIDER_TOKEN = "InvalidProviderToken"  # noqa: S105
    MISSING_PROVIDER_TOKEN = "MissingProviderToken"  # noqa: S105
    BAD_PATH = "BadPath"
    METHOD_NOT_ALLOWED = "MethodNotAllowed"
    EXPIRED_TOKEN = "ExpiredToken"  # noqa: S105
    UNREGISTERED = "Unregistered"
    PAYLOAD_TOO_LARGE = "PayloadTooLarge"
    TOO_MANY_PROVIDER_TOKEN_UPDATES = "TooManyProviderTokenUpdates"  # noqa: S105
    TOO_MANY_REQUESTS = "TooManyRequests"
    INTERNAL_SERVER_ERROR = "InternalServerError"
    SERVICE_UNAVAILABLE = "ServiceUnavailable"
    SHUTDOWN = "Shutdown"

    @classmethod
    def from_message(cls, message: str | None) -> APNSReason | None:
        """Recognize a complete reason after removing known server wrappers.

        Args:
            message: Bark's error message with a known push-failure wrapper.

        Returns:
            A known reason, or None for unrecognized or free-form errors.
        """
        if message is None:
            return None
        detail = message.strip()
        reason = detail
        for prefix in ("push failed: ", "APNS push failed: "):
            reason = reason.removeprefix(prefix)
        if reason == detail:
            return None
        try:
            return cls(reason)
        except ValueError:
            return None


class APIError(BaarkError):
    """The server reported an HTTP or Bark application error.

    Attributes:
        status_code: HTTP response status.
        code: Bark's application status, when available.
        server_message: Unmodified server message, for explicit inspection.
        apns_reason: Recognized APNs rejection, even when Bark wraps it in HTTP 500.
    """

    def __init__(
        self,
        *,
        status_code: int,
        code: int | None = None,
        server_message: str | None = None,
    ) -> None:
        """Record statuses and known APNs reasons without echoing raw response text.

        Args:
            status_code: HTTP status.
            code: Optional Bark application status.
            server_message: Optional server-provided detail.
        """
        self.status_code = status_code
        self.code = code
        self.server_message = server_message
        self.apns_reason = APNSReason.from_message(server_message)
        detail = f"Bark request failed (HTTP {status_code}, code {code})."
        if self.apns_reason is not None:
            detail += f" APNs reason: {self.apns_reason}."
        super().__init__(detail)


class BatchError(BaarkError):
    """One or more recipients failed; inspect ``response.deliveries``."""

    def __init__(self, response: Response) -> None:
        """Keep the complete batch response, including successful recipients.

        Args:
            response: Parsed batch response.
        """
        self.response = response
        super().__init__(
            f"Bark rejected {len(response.failures)} of "
            f"{len(response.deliveries)} deliveries."
        )


def invalid(message: str) -> NoReturn:
    """Raise a validation error with a caller-supplied explanation.

    Args:
        message: Explanation that contains no secret values.

    Raises:
        ValidationError: Always.
    """
    raise ValidationError(message)
