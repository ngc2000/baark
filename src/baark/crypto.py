# Copyright (c) 2026 doabell.
"""Bark-compatible AES using PyCryptodome, with no OpenSSL dependency."""

from __future__ import annotations

import base64
import binascii
import secrets
import string
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from baark.errors import EncryptionError

type ModeValue = Literal["GCM", "CBC", "ECB"]
type KeyEncoding = Literal["text", "hex", "base64"]
_KEY_LENGTHS = (16, 24, 32)
_GCM_NONCE_LENGTH = 12
_CBC_IV_LENGTH = 16
_TAG_LENGTH = 16
_TOKEN_ALPHABET = string.ascii_letters + string.digits + "-_"


class EncryptionMode(StrEnum):
    """AES modes supported by the Bark app."""

    GCM = "GCM"
    CBC = "CBC"
    ECB = "ECB"


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """A base64 ciphertext and optional literal-text IV for Bark."""

    ciphertext: str = field(repr=False)
    iv: str | None = field(default=None, repr=False)

    def to_payload(self) -> dict[str, str]:
        """Return the fields to send to Bark."""
        result = {"ciphertext": self.ciphertext}
        if self.iv is not None:
            result["iv"] = self.iv
        return result


@dataclass(frozen=True, slots=True)
class Encryption:
    """Encryption settings matching the values entered in the Bark app.

    Args:
        key: Literal printable ASCII key, exactly 16, 24, or 32 bytes.
        mode: GCM by default. CBC and ECB are compatibility modes.
        iv: Optional fixed CBC IV for older app configurations. GCM always
            generates a fresh nonce; fixed GCM nonces are rejected.

    GCM uses no padding and appends its authentication tag to the ciphertext.
    CBC and ECB use PKCS7 padding. The key is never sent to the server.
    """

    key: str = field(repr=False)
    mode: EncryptionMode | ModeValue = field(default=EncryptionMode.GCM, kw_only=True)
    iv: str | None = field(default=None, kw_only=True, repr=False)

    def __post_init__(self) -> None:
        """Validate settings against both AES and Bark's text-based format."""
        if (
            not isinstance(self.key, str)
            or not self.key.isascii()
            or not self.key.isprintable()
        ):
            message = (
                "The encryption key must be printable ASCII text as entered in Bark."
            )
            raise EncryptionError(message)
        if len(self.key) not in _KEY_LENGTHS:
            message = (
                "The encryption key must contain exactly 16, 24, or 32 characters."
            )
            raise EncryptionError(message)
        if self.mode not in EncryptionMode:
            message = "Encryption mode must be GCM, CBC, or ECB."
            raise EncryptionError(message)
        if self.iv is not None:
            if self.mode != EncryptionMode.CBC:
                message = (
                    "A fixed IV is only supported for CBC; GCM needs a fresh nonce."
                )
                raise EncryptionError(message)
            _validate_iv(self.iv, _CBC_IV_LENGTH)

    @classmethod
    def generate(
        cls,
        *,
        bits: Literal[128, 192, 256] = 256,
        mode: EncryptionMode | ModeValue = EncryptionMode.GCM,
    ) -> Encryption:
        """Generate a printable key that can be copied into Bark's settings.

        Args:
            bits: AES key size; the generated text has six random bits per byte.
            mode: AES mode to configure in the app.

        Returns:
            Encryption settings with a newly generated key.
        """
        if bits not in (128, 192, 256):
            message = "AES key size must be 128, 192, or 256 bits."
            raise EncryptionError(message)
        return cls(key=_random_text(bits // 8), mode=mode)

    @classmethod
    def from_key(
        cls,
        key: str | bytes,
        *,
        encoding: KeyEncoding = "text",
        mode: EncryptionMode | ModeValue = EncryptionMode.GCM,
        iv: str | None = None,
    ) -> Encryption:
        """Import an existing Bark key without changing or regenerating it.

        Args:
            key: Literal key text/ASCII bytes, or its hex/base64 representation.
            encoding: Explicit input encoding; never inferred from the contents.
            mode: Encryption mode matching the app's settings.
            iv: Optional fixed CBC IV for an existing configuration.

        Returns:
            Encryption settings using the decoded literal key. Enter that text
            in Bark, not the hex/base64 representation.

        Raises:
            EncryptionError: For malformed encoding or a decoded key that is not
                16, 24, or 32 printable ASCII characters.
        """
        if not isinstance(key, (str, bytes)):
            message = "The imported key must be text or bytes."
            raise EncryptionError(message)
        if encoding not in ("text", "hex", "base64"):
            message = "Key encoding must be text, hex, or base64."
            raise EncryptionError(message)
        try:
            text = key.decode("ascii") if isinstance(key, bytes) else key
            if encoding == "hex":
                text = bytes.fromhex(text).decode("ascii")
            elif encoding == "base64":
                text = base64.b64decode(text, validate=True).decode("ascii")
        except ValueError:
            message = "Could not decode the key using the requested encoding."
            raise EncryptionError(message) from None
        return cls(text, mode=mode, iv=iv)

    @property
    def algorithm(self) -> str:
        """Algorithm label displayed in the app, such as ``AES256``."""
        return f"AES{len(self.key) * 8}"

    @property
    def padding(self) -> str:
        """Padding option to select in the app."""
        return "noPadding" if self.mode == EncryptionMode.GCM else "pkcs7"

    def encrypt(self, plaintext: str) -> EncryptedPayload:
        """Encrypt UTF-8 text using a fresh IV unless fixed CBC was requested.

        Args:
            plaintext: A JSON notification string.

        Returns:
            Ciphertext and IV in the app's expected representation.
        """
        key = self.key.encode("ascii")
        data = plaintext.encode("utf-8")
        if self.mode == EncryptionMode.GCM:
            iv = _random_text(_GCM_NONCE_LENGTH)
            cipher = AES.new(
                key, AES.MODE_GCM, nonce=iv.encode("ascii"), mac_len=_TAG_LENGTH
            )
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return EncryptedPayload(_encode(ciphertext + tag), iv)
        if self.mode == EncryptionMode.CBC:
            iv = self.iv if self.iv is not None else _random_text(_CBC_IV_LENGTH)
            ciphertext = AES.new(key, AES.MODE_CBC, iv=iv.encode("ascii")).encrypt(
                pad(data, AES.block_size)
            )
            return EncryptedPayload(_encode(ciphertext), iv)
        # ECB is required for interoperability with existing Bark configurations.
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(data, AES.block_size))
        return EncryptedPayload(_encode(ciphertext))

    def decrypt(self, payload: EncryptedPayload) -> str:
        """Decrypt a payload, verifying its authentication tag when using GCM.

        Args:
            payload: Ciphertext and IV received from ``encrypt`` or another sender.

        Returns:
            The original UTF-8 text.

        Raises:
            EncryptionError: For an invalid IV, ciphertext, padding, or GCM tag.
        """
        try:
            data = base64.b64decode(payload.ciphertext, validate=True)
            plaintext = self._decrypt_bytes(data, payload.iv)
            return plaintext.decode("utf-8")
        except (ValueError, binascii.Error) as error:
            message = (
                "Could not decrypt the payload; "
                "check the key, mode, IV, and ciphertext."
            )
            raise EncryptionError(message) from error

    def _decrypt_bytes(self, data: bytes, iv: str | None) -> bytes:
        key = self.key.encode("ascii")
        if self.mode == EncryptionMode.GCM:
            iv = _validate_iv(iv, _GCM_NONCE_LENGTH)
            if len(data) < _TAG_LENGTH:
                message = "GCM ciphertext is missing its authentication tag."
                raise EncryptionError(message)
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv.encode("ascii"))
            return cipher.decrypt_and_verify(data[:-_TAG_LENGTH], data[-_TAG_LENGTH:])
        if self.mode == EncryptionMode.CBC:
            iv = iv if iv is not None else self.iv
            iv = _validate_iv(iv, _CBC_IV_LENGTH)
            data = AES.new(key, AES.MODE_CBC, iv=iv.encode("ascii")).decrypt(data)
        else:
            if iv is not None:
                message = "ECB ciphertext must not include an IV."
                raise EncryptionError(message)
            data = AES.new(key, AES.MODE_ECB).decrypt(data)
        return unpad(data, AES.block_size)


def _validate_iv(iv: str | None, length: int) -> str:
    if (
        not isinstance(iv, str)
        or not iv.isascii()
        or not iv.isprintable()
        or len(iv) != length
    ):
        message = f"The IV must contain exactly {length} printable ASCII characters."
        raise EncryptionError(message)
    return iv


def _random_text(length: int) -> str:
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(length))


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
