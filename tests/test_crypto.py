# Copyright (c) 2026 doabell.
"""Independent vectors, authentication, and Bark text-format compatibility."""

import base64
import unittest
from typing import cast
from unittest.mock import patch

from baark import (
    EncryptedPayload,
    Encryption,
    EncryptionError,
    EncryptionMode,
    KeyEncoding,
)

# GCM vectors computed independently with cryptography's AESGCM implementation.
# No cryptography or OpenSSL installation is needed to run these tests.
_PLAINTEXT = '{"body":"你好 👋","badge":0}'
_GCM_IV = "123456789012"
_GCM_VECTORS = (
    (
        "0123456789abcdef",
        "vXMgmo8XpZETdSbc6oKlVZRVQlG3tyBTFexlDqa7MDAiKveR85wq/LLGpTsGCraP",
    ),
    (
        "0123456789abcdefghijklmn",
        "wuMiPE9GZ3qqRBxS0GlPGbwK4gwU4mMp+OZcRT6V3j12HmPeMLWC77AyWAGyU57p",
    ),
    (
        "0123456789abcdefghijklmnopqrstuv",
        "HYDeaxk0/U4cw8QQAWnMvpo15SFmirf3/JAxNHhRPLtwOFtne6bYv62XIxwdRG2c",
    ),
)


class EncryptionTests(unittest.TestCase):
    """Verify the encryption format independently from request serialization."""

    def test_official_bark_cbc_vector(self) -> None:
        """Match the example published in Finb/Bark docs/en-us/encryption.md."""
        encryption = Encryption("1234567890123456", mode="CBC", iv="1111111111111111")
        result = encryption.encrypt('{"body": "test", "sound": "birdsong"}')
        self.assertEqual(
            result.ciphertext,
            "d3QhjQjP5majvNt5CjsvFWwqqj2gKl96RFj5OO+u6ynTt7lkyigDYNA3abnnCLpr",
        )
        self.assertEqual(result.iv, "1111111111111111")

    def test_independent_gcm_vectors(self) -> None:
        """All key sizes produce the expected combined ciphertext and tag."""
        for key, ciphertext in _GCM_VECTORS:
            with self.subTest(key_size=len(key)):
                encryption = Encryption(key)
                with patch("baark.crypto.secrets.choice", side_effect=_GCM_IV):
                    result = encryption.encrypt(_PLAINTEXT)
                self.assertEqual(result, EncryptedPayload(ciphertext, _GCM_IV))
                self.assertEqual(encryption.decrypt(result), _PLAINTEXT)

    def test_all_modes_and_key_sizes(self) -> None:
        """Support all nine combinations exposed by the Bark app."""
        for mode in EncryptionMode:
            for size in (16, 24, 32):
                with self.subTest(mode=mode, size=size):
                    encryption = Encryption("K" * size, mode=mode)
                    for text in ("", "x" * 16, _PLAINTEXT):
                        result = encryption.encrypt(text)
                        self.assertEqual(encryption.decrypt(result), text)

    def test_fresh_literal_ivs(self) -> None:
        """IVs must be fresh printable text of the app's expected length."""
        for mode, size in (("GCM", 12), ("CBC", 16)):
            with self.subTest(mode=mode):
                encryption = Encryption("K" * 32, mode=EncryptionMode(mode))
                results = [encryption.encrypt("same text") for _ in range(20)]
                self.assertEqual(len({item.iv for item in results}), len(results))
                for item in results:
                    self.assertIsNotNone(item.iv)
                    self.assertEqual(len(item.iv or ""), size)
                    self.assertTrue((item.iv or "").isascii())

    def test_gcm_detects_tampering(self) -> None:
        """Neither modified ciphertext nor a modified tag may be decrypted."""
        encryption = Encryption("K" * 32)
        result = encryption.encrypt(_PLAINTEXT)
        raw = base64.b64decode(result.ciphertext)
        for index in (0, len(raw) - 1):
            changed = bytearray(raw)
            changed[index] ^= 1
            payload = EncryptedPayload(base64.b64encode(changed).decode(), result.iv)
            with self.subTest(index=index), self.assertRaises(EncryptionError):
                encryption.decrypt(payload)
        with self.assertRaises(EncryptionError):
            Encryption("X" * 32).decrypt(result)

    def test_invalid_keys_and_fixed_gcm_ivs(self) -> None:
        """Reject keys the app cannot represent and fixed GCM nonces."""
        for key in ("", "short", "K" * 33, "é" * 16, "\0" * 16):
            with self.subTest(length=len(key)), self.assertRaises(EncryptionError):
                Encryption(key)
        for iv in ("123456789012", "1234567890123456"):
            with self.subTest(iv_length=len(iv)), self.assertRaises(EncryptionError):
                Encryption("K" * 32, mode="GCM", iv=iv)
        with self.assertRaises(EncryptionError):
            Encryption("K" * 16, mode="ECB", iv="1234567890123456")

    def test_invalid_ciphertext_and_iv(self) -> None:
        """Malformed base64, padding, tags, and IV lengths fail clearly."""
        cases = (
            EncryptedPayload("invalid!!!", _GCM_IV),
            EncryptedPayload("YQ==", _GCM_IV),
            EncryptedPayload("YQ==", "1234567890123456"),
            EncryptedPayload("YQ=="),
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(EncryptionError):
                Encryption("K" * 32).decrypt(payload)
        with self.assertRaises(EncryptionError):
            Encryption("K" * 16, mode="CBC").decrypt(EncryptedPayload("YQ==", "I" * 16))

    def test_generate_app_settings(self) -> None:
        """Generated keys expose matching algorithm and padding labels."""
        settings = Encryption.generate()
        self.assertEqual(len(settings.key), 32)
        self.assertEqual(settings.algorithm, "AES256")
        self.assertEqual(settings.padding, "noPadding")
        self.assertNotIn(settings.key, repr(settings))
        self.assertEqual(Encryption.generate(bits=128, mode="CBC").padding, "pkcs7")

    def test_fixed_cbc_fallback_iv(self) -> None:
        """An older app's stored CBC IV can be supplied explicitly."""
        settings = Encryption("K" * 16, mode="CBC", iv="I" * 16)
        payload = settings.encrypt("hello")
        self.assertEqual(
            settings.decrypt(EncryptedPayload(payload.ciphertext)), "hello"
        )

    def test_import_existing_keys(self) -> None:
        """Imported text, bytes, hex, and base64 decrypt independent GCM vectors."""
        for key, ciphertext in _GCM_VECTORS:
            inputs: tuple[tuple[KeyEncoding, str], ...] = (
                ("text", key),
                ("hex", key.encode().hex()),
                ("base64", base64.b64encode(key.encode()).decode()),
            )
            for encoding, value in inputs:
                for imported in (value, value.encode()):
                    with self.subTest(size=len(key), encoding=encoding):
                        settings = Encryption.from_key(imported, encoding=encoding)
                        self.assertEqual(settings.key, key)
                        self.assertNotIn(key, repr(settings))
                        self.assertEqual(
                            settings.decrypt(EncryptedPayload(ciphertext, _GCM_IV)),
                            _PLAINTEXT,
                        )

    def test_import_encoding_is_explicit(self) -> None:
        """Hex-looking literal keys must not be silently decoded or replaced."""
        text = "30313233343536373839616263646566"
        literal = Encryption.from_key(text)
        decoded = Encryption.from_key(text, encoding="hex")
        self.assertEqual(literal.key, text)
        self.assertEqual(literal.algorithm, "AES256")
        self.assertEqual(decoded.key, "0123456789abcdef")
        self.assertEqual(decoded.algorithm, "AES128")
        self.assertEqual(literal, Encryption(text))

    def test_import_existing_cbc_settings(self) -> None:
        """Key import preserves the mode and the existing app's CBC IV."""
        settings = Encryption.from_key(
            b"1234567890123456", mode="CBC", iv="1111111111111111"
        )
        self.assertEqual(
            settings.encrypt('{"body": "test", "sound": "birdsong"}').ciphertext,
            "d3QhjQjP5majvNt5CjsvFWwqqj2gKl96RFj5OO+u6ynTt7lkyigDYNA3abnnCLpr",
        )

    def test_invalid_imports(self) -> None:
        """Reject malformed encodings and keys that cannot be entered in Bark."""
        cases: tuple[tuple[object, str], ...] = (
            (None, "text"),
            ("K" * 16, "auto"),
            (b"\xff" * 16, "text"),
            ("zz" * 16, "hex"),
            ("f", "hex"),
            ("ff" * 16, "hex"),
            ("!!!!", "base64"),
            ("YQ", "base64"),
            ("YQ==", "base64"),
            ("é" * 16, "base64"),
            (base64.b64encode(b"\0" * 16), "base64"),
            ("K" * 16 + "\n", "text"),
        )
        for key, encoding in cases:
            with self.subTest(encoding=encoding), self.assertRaises(EncryptionError):
                Encryption.from_key(
                    cast("str | bytes", key), encoding=cast("KeyEncoding", encoding)
                )

    def test_invalid_algorithm_settings(self) -> None:
        """Unsupported AES modes, key sizes, and CBC IVs fail during setup."""
        with self.assertRaises(EncryptionError):
            Encryption("K" * 16, mode="CTR")  # ty: ignore[invalid-argument-type]
        with self.assertRaises(EncryptionError):
            Encryption.generate(bits=64)  # ty: ignore[invalid-argument-type]
        with self.assertRaises(EncryptionError):
            Encryption.from_key("K" * 16, mode="GCM", iv=_GCM_IV)
        for iv in ("short", "é" * 16, "\0" * 16):
            with self.subTest(iv_length=len(iv)), self.assertRaises(EncryptionError):
                Encryption("K" * 16, mode="CBC", iv=iv)

    def test_ecb_payload_has_no_iv(self) -> None:
        """ECB pass-through payloads omit IVs and reject unexpected ones."""
        settings = Encryption.from_key("K" * 16, mode="ECB")
        result = settings.encrypt(_PLAINTEXT)
        self.assertEqual(result.to_payload(), {"ciphertext": result.ciphertext})
        with self.assertRaises(EncryptionError):
            settings.decrypt(EncryptedPayload(result.ciphertext, "I" * 16))
