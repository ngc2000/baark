# Copyright (c) 2026 doabell.
"""baark: typed Python bindings for Bark notifications at https://bark.day.app.

Use ``Baark`` or ``AsyncBaark`` for pooled connections, or ``send``/``async_send``
for one-off notifications. Encryption uses PyCryptodome.
"""

from baark.client import AsyncBaark, Baark, async_send, send
from baark.crypto import EncryptedPayload, Encryption, EncryptionMode, KeyEncoding
from baark.errors import (
    APIError,
    APNSReason,
    BaarkError,
    BatchError,
    EncryptionError,
    ProtocolError,
    TransportError,
    ValidationError,
)
from baark.models import (
    Action,
    Delivery,
    Endpoint,
    JSONValue,
    Level,
    Message,
    MessageOptions,
    Registration,
    Response,
    ServerInfo,
    Sound,
)

__all__ = [
    "APIError",
    "APNSReason",
    "Action",
    "AsyncBaark",
    "Baark",
    "BaarkError",
    "BatchError",
    "Delivery",
    "EncryptedPayload",
    "Encryption",
    "EncryptionError",
    "EncryptionMode",
    "Endpoint",
    "JSONValue",
    "KeyEncoding",
    "Level",
    "Message",
    "MessageOptions",
    "ProtocolError",
    "Registration",
    "Response",
    "ServerInfo",
    "Sound",
    "TransportError",
    "ValidationError",
    "async_send",
    "send",
]
