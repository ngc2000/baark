# Copyright (c) 2026 doabell.
"""Shared request construction and strict response parsing."""

from __future__ import annotations

import json
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, cast
from urllib.parse import quote, unquote, urlencode

import httpx2

from baark.crypto import Encryption
from baark.errors import APIError, ProtocolError, invalid
from baark.models import (
    Delivery,
    Endpoint,
    EndpointValue,
    JSONValue,
    Message,
    MessageOptions,
    Registration,
    Response,
    ServerInfo,
    normalize_options,
)

DEFAULT_SERVER = "https://api.day.app"
_MAX_DEVICE_TOKEN_LENGTH = 160
_MESSAGE_QUERY_FIELDS = frozenset(
    name.lower()
    for name in (
        *MessageOptions.__annotations__,
        "body",
        "autoCopy",
        "isArchive",
        "device_key",
        "device_keys",
        "device_token",
    )
)

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class Config:
    """HTTP-independent settings shared by sync and async clients."""

    server_url: str
    device_key: str | None = field(repr=False)
    encryption: Encryption | None
    defaults: MessageOptions = field(repr=False)
    endpoint: Endpoint

    def url(self, path: str) -> str:
        """Append an endpoint while preserving reverse-proxy path prefixes.

        Args:
            path: Relative endpoint path.

        Returns:
            An absolute URL.
        """
        return f"{self.server_url}/{path.lstrip('/')}"


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """A complete request that either HTTP client can send."""

    method: str
    url: str = field(repr=False)
    content: bytes | None = field(default=None, repr=False)
    content_type: str | None = None
    expected_keys: tuple[str, ...] | None = field(default=None, repr=False)
    query_fields: frozenset[str] = field(default=_MESSAGE_QUERY_FIELDS, repr=False)


def configure(
    device_key: str | None,
    *,
    server_url: str | None,
    encryption: Encryption | None,
    defaults: MessageOptions,
    endpoint: Endpoint | EndpointValue,
) -> Config:
    """Validate configuration and optionally split a copied device URL.

    Args:
        device_key: A key or a URL ending in the key.
        server_url: Optional server URL, including a reverse-proxy prefix.
        encryption: Optional payload encryption.
        defaults: Default message options.
        endpoint: Default request format.

    Returns:
        Validated client configuration.
    """
    if device_key is not None and not isinstance(device_key, str):
        invalid("device_key must be a string or a device URL.")
    if device_key is not None and "://" in device_key:
        if server_url is not None:
            invalid("Pass either a device URL or a separate key and server_url.")
        device_url = _server_url(device_key)
        server_url, separator, encoded_key = device_url.rpartition("/")
        if not separator or not encoded_key or server_url.endswith(":/"):
            invalid("A device URL must end in a device key.")
        device_key = unquote(encoded_key)
    if device_key is not None:
        validate_key(device_key)
    if encryption is not None and not isinstance(encryption, Encryption):
        invalid("encryption must be an Encryption instance.")
    selected_endpoint = parse_endpoint(endpoint)
    normalized = normalize_options(defaults)
    Message(**normalized)
    return Config(
        server_url=_server_url(
            server_url if server_url is not None else DEFAULT_SERVER
        ),
        device_key=device_key,
        encryption=encryption,
        defaults=normalized,
        endpoint=selected_endpoint,
    )


def _server_url(value: str) -> str:
    if not isinstance(value, str):
        invalid("server_url must be an absolute HTTP or HTTPS URL.")
    try:
        url = httpx2.URL(value)
    except httpx2.InvalidURL:
        invalid("server_url is not a valid URL.")
    if url.scheme not in {"http", "https"} or not url.host:
        invalid("server_url must be an absolute HTTP or HTTPS URL.")
    if url.username or url.password or url.query or url.fragment:
        invalid("Server URLs cannot contain credentials, query strings, or fragments.")
    return str(url).rstrip("/")


def validate_key(key: str) -> str:
    """Validate a key without including it in diagnostic messages.

    Args:
        key: Device key.

    Returns:
        The validated key.
    """
    if (
        not isinstance(key, str)
        or not key
        or not key.isprintable()
        or any(character.isspace() for character in key)
        or any(character in key for character in "/\\?#")
        or key in {".", ".."}
    ):
        invalid("A device key must be a non-empty URL segment without whitespace.")
    return key


def parse_endpoint(value: Endpoint | EndpointValue) -> Endpoint:
    """Resolve a public endpoint option.

    Args:
        value: An endpoint enum or its string value.

    Returns:
        The endpoint enum.
    """
    try:
        return Endpoint(value)
    except ValueError:
        invalid("endpoint must be push, device, form, or get.")


def prepare_push(  # noqa: PLR0913 - Mirrors the public send options.
    config: Config,
    body: str | Message,
    *,
    options: MessageOptions,
    device_key: str | None,
    device_keys: Sequence[str] | None,
    endpoint: Endpoint | EndpointValue | None,
) -> RequestSpec:
    """Build a push request without performing network I/O.

    Args:
        config: Client configuration.
        body: Text or a reusable message.
        options: Per-call overrides; explicit None removes defaults.
        device_key: Optional single recipient override.
        device_keys: Optional server-side batch recipients.
        endpoint: Optional request format override.

    Returns:
        A request specification ready for either client.
    """
    payload = _message(config, body, options).to_payload()
    query_fields = _query_field_names(payload)
    if config.encryption is not None:
        if "ciphertext" in payload or "iv" in payload:
            invalid(
                "Pre-encrypted ciphertext cannot be combined with client encryption."
            )
        encrypted: dict[str, JSONValue] = dict(
            config.encryption.encrypt(_json(payload)).to_payload()
        )
        # APNs collapse IDs and background deletion are processed before decryption.
        for name in ("id", "delete"):
            if name in payload:
                encrypted[name] = payload[name]
        payload = encrypted

    selected = config.endpoint if endpoint is None else parse_endpoint(endpoint)
    keys = _recipients(config, device_key, device_keys)
    expected = keys if device_keys is not None else None
    if selected != Endpoint.PUSH and device_keys is not None:
        invalid("device_keys batches require the push JSON endpoint.")
    if selected == Endpoint.PUSH:
        if expected is not None:
            payload["device_keys"] = list(keys)
        else:
            payload["device_key"] = keys[0]
        return json_request(
            config, "push", payload, expected_keys=expected, query_fields=query_fields
        )
    path = quote(keys[0], safe="")
    if selected == Endpoint.DEVICE:
        return json_request(config, path, payload, query_fields=query_fields)
    encoded = urlencode(_query_fields(payload))
    if selected == Endpoint.GET:
        return RequestSpec(
            "GET",
            f"{config.url(path)}?{encoded}",
            query_fields=query_fields,
        )
    return RequestSpec(
        "POST",
        config.url(path),
        encoded.encode("utf-8"),
        "application/x-www-form-urlencoded; charset=utf-8",
        query_fields=query_fields,
    )


def _message(config: Config, body: str | Message, options: MessageOptions) -> Message:
    merged = normalize_options(config.defaults)
    if isinstance(body, Message):
        merged.update(body.options())
        body = body.body
    merged.update(normalize_options(options))
    return Message(body, **merged)


def _recipients(
    config: Config, device_key: str | None, device_keys: Sequence[str] | None
) -> tuple[str, ...]:
    if device_keys is not None:
        if device_key is not None:
            invalid("Specify device_key or device_keys, not both.")
        if isinstance(device_keys, (str, bytes)) or not device_keys:
            invalid("device_keys must be a non-empty sequence of device keys.")
        return tuple(validate_key(key) for key in device_keys)
    key = config.device_key if device_key is None else device_key
    if key is None:
        invalid("Provide a device key to send a notification.")
    return (validate_key(key),)


def _query_fields(payload: dict[str, JSONValue]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in payload.items():
        if isinstance(value, (dict, list)):
            invalid("Structured extension fields require a JSON endpoint.")
        result[name] = str(value) if value is not None else ""
    return result


def _query_field_names(payload: dict[str, JSONValue]) -> frozenset[str]:
    names = set(payload)
    for value in payload.values():
        if isinstance(value, dict):
            names.update(value)
    return _MESSAGE_QUERY_FIELDS | frozenset(name.lower() for name in names)


def _json(payload: dict[str, JSONValue]) -> str:
    return json.dumps(
        payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )


def json_request(
    config: Config,
    path: str,
    payload: dict[str, JSONValue],
    *,
    expected_keys: tuple[str, ...] | None = None,
    query_fields: frozenset[str] = frozenset(),
) -> RequestSpec:
    """Build a JSON POST request.

    Args:
        config: Client configuration.
        path: Endpoint path relative to the server prefix.
        payload: JSON object to send.
        expected_keys: Recipients expected in a batch response.
        query_fields: Message fields to protect even when hidden by encryption.

    Returns:
        Encoded request specification.
    """
    return RequestSpec(
        "POST",
        config.url(path),
        _json(payload).encode("utf-8"),
        "application/json; charset=utf-8",
        expected_keys,
        _query_field_names(payload) | query_fields,
    )


def registration_request(
    config: Config, device_token: str, device_key: str | None
) -> RequestSpec:
    """Build a registration request without implicitly reusing the client key.

    Args:
        config: Client configuration.
        device_token: APNs device token obtained from the app.
        device_key: Explicit existing or custom key; None asks for a new key.

    Returns:
        A JSON POST to the registration endpoint.
    """
    if (
        not isinstance(device_token, str)
        or not device_token
        or len(device_token) > _MAX_DEVICE_TOKEN_LENGTH
    ):
        invalid("device_token must contain between 1 and 160 characters.")
    payload: dict[str, JSONValue] = {"device_token": device_token}
    if device_key is not None:
        payload["device_key"] = validate_key(device_key)
    return json_request(config, "register", payload)


def check_request(config: Config, device_key: str | None) -> RequestSpec:
    """Build a registration check for a supplied or configured key.

    Args:
        config: Client configuration.
        device_key: Optional key override.

    Returns:
        A GET request to the registration-check endpoint.
    """
    key = _recipients(config, device_key, None)[0]
    return RequestSpec("GET", config.url(f"register/{quote(key, safe='')}"))


def read_json(response: httpx2.Response) -> dict[str, JSONValue]:
    """Decode an object response and detect HTTP errors.

    Args:
        response: HTTP response.

    Returns:
        A decoded JSON object.

    Raises:
        APIError: For an HTTP error.
        ProtocolError: For a malformed successful response.
    """
    raw: object = None
    with suppress(ValueError):
        raw = response.json()
    if not response.is_success:
        code = raw.get("code") if isinstance(raw, dict) else None
        message = raw.get("message") if isinstance(raw, dict) else None
        raise APIError(
            status_code=response.status_code,
            code=code if type(code) is int else None,
            server_message=message if isinstance(message, str) else None,
        )
    if not isinstance(raw, dict):
        message = "Expected a Bark JSON object; received an invalid response."
        raise ProtocolError(message)
    return cast("dict[str, JSONValue]", raw)


def parse_response(
    response: httpx2.Response, *, expected_keys: tuple[str, ...] | None = None
) -> Response:
    """Validate a Bark envelope and every expected batch outcome.

    Args:
        response: HTTP response.
        expected_keys: Recipients of the corresponding batch, if any.

    Returns:
        A typed response.

    Raises:
        APIError: For HTTP or Bark application errors.
        ProtocolError: For malformed or incomplete responses.
        BatchError: When any batch recipient failed.
    """
    raw = read_json(response)
    code = raw.get("code")
    message = raw.get("message")
    timestamp = raw.get("timestamp")
    if (
        type(code) is not int
        or not isinstance(message, str)
        or (timestamp is not None and type(timestamp) is not int)
    ):
        detail = "Bark response has invalid or missing code, message, or timestamp."
        raise ProtocolError(detail)
    if code != HTTPStatus.OK:
        raise APIError(
            status_code=response.status_code, code=code, server_message=message
        )
    deliveries = ()
    if expected_keys is not None:
        deliveries = _deliveries(raw.get("data"), expected_keys)
    result = Response(
        code, message, timestamp, raw.get("data"), deliveries, response.status_code
    )
    result.raise_for_status()
    return result


def _deliveries(
    data: JSONValue, expected_keys: tuple[str, ...]
) -> tuple[Delivery, ...]:
    if not isinstance(data, list):
        message = "Bark batch response is missing per-device results."
        raise ProtocolError(message)
    result: list[Delivery] = []
    for item in data:
        if not isinstance(item, dict):
            message = "Bark batch result must be an object."
            raise ProtocolError(message)
        key, code, detail = (
            item.get("device_key"),
            item.get("code"),
            item.get("message", ""),
        )
        if (
            not isinstance(key, str)
            or type(code) is not int
            or not isinstance(detail, str)
        ):
            message = "Bark batch result has invalid or missing fields."
            raise ProtocolError(message)
        result.append(Delivery(key, code, detail))
    if Counter(item.device_key for item in result) != Counter(expected_keys):
        message = "Bark batch results do not match the requested recipients."
        raise ProtocolError(message)
    return tuple(result)


def parse_info(response: httpx2.Response) -> ServerInfo:
    """Read the unwrapped server-info object.

    Args:
        response: HTTP response from /info.

    Returns:
        Validated server information.
    """
    raw = read_json(response)
    names = ("version", "build", "arch", "commit")
    if (
        any(not isinstance(raw.get(name), str) for name in names)
        or type(raw.get("devices")) is not int
    ):
        message = "Bark server-info response has invalid or missing fields."
        raise ProtocolError(message)
    return ServerInfo(
        version=cast("str", raw["version"]),
        build=cast("str", raw["build"]),
        arch=cast("str", raw["arch"]),
        commit=cast("str", raw["commit"]),
        devices=cast("int", raw["devices"]),
    )


def parse_registration(response: httpx2.Response) -> Registration:
    """Validate the registration envelope and extract device credentials.

    Args:
        response: HTTP response from /register.

    Returns:
        Registered device credentials.
    """
    data = parse_response(response).data
    if not isinstance(data, dict):
        message = "Bark registration response is missing device credentials."
        raise ProtocolError(message)
    key = data.get("device_key", data.get("key"))
    token = data.get("device_token")
    if not isinstance(key, str) or not key or not isinstance(token, str) or not token:
        message = "Bark registration response has invalid device credentials."
        raise ProtocolError(message)
    return Registration(key, token)


def parse_health(response: httpx2.Response) -> str:
    """Validate the plain-text response used by the root and health endpoints.

    Args:
        response: HTTP response.

    Returns:
        The string ``ok``.
    """
    if not response.is_success:
        raise APIError(status_code=response.status_code)
    if response.text.strip() != "ok":
        message = "Expected 'ok' from the Bark health endpoint."
        raise ProtocolError(message)
    return "ok"
