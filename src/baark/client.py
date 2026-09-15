# Copyright (c) 2026 doabell.
"""Synchronous and asynchronous clients with the same notification interface."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Self, Unpack, cast, override
from urllib.parse import quote

import httpx2

from baark._protocol import (
    RequestSpec,
    check_request,
    configure,
    parse_health,
    parse_info,
    parse_registration,
    parse_response,
    prepare_push,
    registration_request,
)
from baark.crypto import Encryption, ModeValue
from baark.errors import TransportError, invalid
from baark.models import (
    Endpoint,
    EndpointValue,
    Message,
    MessageOptions,
    Registration,
    Response,
    ServerInfo,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType


class _Base[HTTPClient: (httpx2.Client, httpx2.AsyncClient)]:
    _http: HTTPClient
    _timeout: float | httpx2.Timeout | None

    def __init__(
        self,
        device_key: str | None = None,
        *,
        server_url: str | None = None,
        encryption: Encryption | None = None,
        endpoint: Endpoint | EndpointValue = Endpoint.PUSH,
        **defaults: Unpack[MessageOptions],
    ) -> None:
        self._config = configure(
            device_key,
            server_url=server_url,
            encryption=encryption,
            defaults=defaults,
            endpoint=endpoint,
        )
        self._closed = False

    @property
    def server_url(self) -> str:
        """The normalized server URL, including any reverse-proxy prefix."""
        return self._config.server_url

    @property
    def mcp_url(self) -> str:
        """The URL to give a standard MCP client; it may contain the device key."""
        path = "mcp"
        if self._config.device_key is not None:
            path += f"/{quote(self._config.device_key, safe='')}"
        return self._config.url(path)

    @classmethod
    def from_env(cls, **defaults: Unpack[MessageOptions]) -> Self:
        """Create a client from explicitly requested environment configuration.

        Reads BAARK_DEVICE_KEY, BAARK_SERVER_URL, BAARK_ENCRYPTION_KEY,
        BAARK_ENCRYPTION_MODE, and BAARK_ENCRYPTION_IV. No files are read.

        Args:
            **defaults: Default notification options.

        Returns:
            A new client. Its device key is required only when sending.
        """
        encryption = None
        key = os.environ.get("BAARK_ENCRYPTION_KEY")
        mode = os.environ.get("BAARK_ENCRYPTION_MODE")
        iv = os.environ.get("BAARK_ENCRYPTION_IV")
        if key is not None:
            encryption = Encryption(key, mode=cast("ModeValue", mode or "GCM"), iv=iv)
        elif mode is not None or iv is not None:
            invalid(
                "BAARK_ENCRYPTION_MODE and BAARK_ENCRYPTION_IV require "
                "BAARK_ENCRYPTION_KEY."
            )
        return cls(
            os.environ.get("BAARK_DEVICE_KEY"),
            server_url=os.environ.get("BAARK_SERVER_URL"),
            encryption=encryption,
            **defaults,
        )

    def build_url(
        self,
        body: str | Message = "",
        *,
        device_key: str | None = None,
        **options: Unpack[MessageOptions],
    ) -> str:
        """Build an encoded GET URL without sending a notification.

        Args:
            body: Notification text or message.
            device_key: Optional single-device override.
            **options: Notification options overriding client defaults.

        Returns:
            A URL containing the device key and payload, encrypted if configured.
        """
        return prepare_push(
            self._config,
            body,
            options=options,
            device_key=device_key,
            device_keys=None,
            endpoint=Endpoint.GET,
        ).url

    def _ensure_open(self) -> None:
        if self._closed or self._http.is_closed:
            message = (
                "This Baark client is closed. Create a new client to send requests."
            )
            raise TransportError(message)

    def _build_request(self, spec: RequestSpec) -> httpx2.Request:
        headers = {"Content-Type": spec.content_type} if spec.content_type else {}
        request = self._http.build_request(
            spec.method,
            spec.url,
            content=spec.content,
            headers=headers,
            timeout=self._timeout,
        )
        # Bark gives query fields precedence over JSON. Keep HTTP defaults from
        # changing notification content, routing, or lifecycle controls.
        query = httpx2.QueryParams(
            [
                (name, value)
                for name, value in self._http.params.multi_items()
                if name.lower() not in spec.query_fields
            ]
        ).merge(httpx2.URL(spec.url).params)
        request.url = request.url.copy_with(query=str(query).encode("ascii") or None)
        return request

    @override
    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(server_url={self.server_url!r}, "
            f"encrypted={self._config.encryption is not None})"
        )


class Baark(_Base[httpx2.Client]):
    """Reusable synchronous client for Bark.

    Args:
        device_key: Device key or a URL ending in the key. Omit for server utilities.
        server_url: Custom server URL, optionally including a path prefix.
        encryption: Optional payload encryption matching the app's settings.
        timeout: Per-request timeout in seconds or an httpx2.Timeout; None disables it.
        auth: Basic-auth credentials or an httpx2.Auth implementation.
        http_client: Optional caller-owned HTTP client for TLS, proxies, or testing.
        endpoint: Default push format: push, device, form, or get.
        **defaults: Default notification fields such as icon, sound, and group.

    Use as a context manager or call ``close``. Injected HTTP clients remain open.
    Requests are not automatically retried or redirected.
    """

    def __init__(  # noqa: PLR0913 - Explicit keyword options aid discovery.
        self,
        device_key: str | None = None,
        *,
        server_url: str | None = None,
        encryption: Encryption | None = None,
        timeout: float | httpx2.Timeout | None = 10.0,
        auth: tuple[str, str] | httpx2.Auth | None = None,
        http_client: httpx2.Client | None = None,
        endpoint: Endpoint | EndpointValue = Endpoint.PUSH,
        **defaults: Unpack[MessageOptions],
    ) -> None:
        """Validate settings and create or borrow an HTTP connection pool."""
        super().__init__(
            device_key,
            server_url=server_url,
            encryption=encryption,
            endpoint=endpoint,
            **defaults,
        )
        if http_client is not None and auth is not None:
            invalid("Configure authentication on the injected http_client.")
        if http_client is not None and not isinstance(http_client, httpx2.Client):
            invalid("Baark requires a synchronous httpx2.Client.")
        self._owns_client = http_client is None
        self._http = (
            http_client if http_client is not None else httpx2.Client(auth=auth)
        )
        self._timeout = timeout

    def send(
        self,
        body: str | Message = "",
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
        endpoint: Endpoint | EndpointValue | None = None,
        **options: Unpack[MessageOptions],
    ) -> Response:
        """Send to one device or a server-side batch.

        Args:
            body: Notification text or a reusable Message.
            device_key: Single-recipient override.
            device_keys: Batch recipients; encrypted batches share one encryption key.
            endpoint: Optional request format override.
            **options: Message fields; None explicitly removes an inherited default.

        Returns:
            A validated server response.

        Raises:
            BatchError: Any batch recipient failed; inspect its response attribute.
            APIError: The server rejected the request.
            ProtocolError: The server returned an invalid response.
            TransportError: The network request failed or the client is closed.
            ValidationError: A setting or message field is invalid.
        """
        spec = prepare_push(
            self._config,
            body,
            options=options,
            device_key=device_key,
            device_keys=device_keys,
            endpoint=endpoint,
        )
        return parse_response(self._request(spec), expected_keys=spec.expected_keys)

    def update(
        self,
        notification_id: str,
        body: str | Message = "",
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
        **options: Unpack[MessageOptions],
    ) -> Response:
        """Replace a notification by sending another message with the same ID.

        Args:
            notification_id: ID used in the original notification.
            body: Replacement text or message.
            device_key: Single-recipient override.
            device_keys: Optional batch recipients.
            **options: Other replacement notification fields.

        Returns:
            The server response. Include all fields needed in the replacement.
        """
        options = _id_options(notification_id, options, delete=False)
        return self.send(
            body, device_key=device_key, device_keys=device_keys, **options
        )

    def delete(
        self,
        notification_id: str,
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
    ) -> Response:
        """Request deletion from the device's notification center and Bark history.

        Args:
            notification_id: ID to delete; Background App Refresh must be enabled.
            device_key: Single-recipient override.
            device_keys: Optional batch recipients.

        Returns:
            Server acceptance of the background deletion request.
        """
        return self.send(
            device_key=device_key,
            device_keys=device_keys,
            id=notification_id,
            delete=True,
        )

    def ping(self) -> Response:
        """Return the validated pong response from ``GET /ping``."""
        return parse_response(
            self._request(RequestSpec("GET", self._config.url("ping")))
        )

    def healthz(self) -> str:
        """Return ``ok`` from ``GET /healthz``, raising on unexpected responses."""
        return parse_health(
            self._request(RequestSpec("GET", self._config.url("healthz")))
        )

    def root(self) -> str:
        """Return ``ok`` from the server's root endpoint."""
        return parse_health(self._request(RequestSpec("GET", self._config.url(""))))

    def info(self) -> ServerInfo:
        """Return typed version and platform information from ``GET /info``."""
        return parse_info(self._request(RequestSpec("GET", self._config.url("info"))))

    def register(
        self, device_token: str, *, device_key: str | None = None
    ) -> Registration:
        """Register an APNs token; omit device_key to request a new Bark key.

        Args:
            device_token: APNs token obtained from the Bark app.
            device_key: Explicit existing/custom key. The client key is not reused.

        Returns:
            Registered device credentials. The client configuration is unchanged.
        """
        return parse_registration(
            self._request(registration_request(self._config, device_token, device_key))
        )

    def check_device(self, device_key: str | None = None) -> Response:
        """Check that a key is registered with the server.

        Args:
            device_key: Optional key override; defaults to the client's key.

        Returns:
            A successful response, or raises if the key is not registered.
        """
        return parse_response(self._request(check_request(self._config, device_key)))

    def _request(self, spec: RequestSpec) -> httpx2.Response:
        self._ensure_open()
        try:
            return self._http.send(self._build_request(spec), follow_redirects=False)
        except httpx2.RequestError as error:
            message = f"Baark HTTP request failed ({type(error).__name__})."
            raise TransportError(message) from None

    def close(self) -> None:
        """Close this SDK client and its HTTP pool if owned; safe to repeat."""
        if not self._closed and self._owns_client:
            self._http.close()
        self._closed = True

    def __enter__(self) -> Self:
        """Enter an open client context."""
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the owned HTTP pool on context exit."""
        self.close()


class AsyncBaark(_Base[httpx2.AsyncClient]):
    """Native async counterpart of Baark, supporting asyncio and Trio via httpx2.

    Constructor and notification options match ``Baark``. Use ``async with`` or
    ``await client.aclose()``. An injected AsyncClient remains caller-owned.
    """

    def __init__(  # noqa: PLR0913 - Matches the synchronous client's interface.
        self,
        device_key: str | None = None,
        *,
        server_url: str | None = None,
        encryption: Encryption | None = None,
        timeout: float | httpx2.Timeout | None = 10.0,
        auth: tuple[str, str] | httpx2.Auth | None = None,
        http_client: httpx2.AsyncClient | None = None,
        endpoint: Endpoint | EndpointValue = Endpoint.PUSH,
        **defaults: Unpack[MessageOptions],
    ) -> None:
        """Validate settings and create or borrow an async HTTP connection pool."""
        super().__init__(
            device_key,
            server_url=server_url,
            encryption=encryption,
            endpoint=endpoint,
            **defaults,
        )
        if http_client is not None and auth is not None:
            invalid("Configure authentication on the injected http_client.")
        if http_client is not None and not isinstance(http_client, httpx2.AsyncClient):
            invalid("AsyncBaark requires an httpx2.AsyncClient.")
        self._owns_client = http_client is None
        self._http = (
            http_client if http_client is not None else httpx2.AsyncClient(auth=auth)
        )
        self._timeout = timeout

    async def send(
        self,
        body: str | Message = "",
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
        endpoint: Endpoint | EndpointValue | None = None,
        **options: Unpack[MessageOptions],
    ) -> Response:
        """Send a notification asynchronously with the same semantics as Baark.send.

        Args:
            body: Notification text or a reusable Message.
            device_key: Single-recipient override.
            device_keys: Batch recipients sharing one encryption configuration.
            endpoint: Optional request format override.
            **options: Message fields overriding client defaults.

        Returns:
            A validated response; raises BatchError for partial batch failures.
        """
        spec = prepare_push(
            self._config,
            body,
            options=options,
            device_key=device_key,
            device_keys=device_keys,
            endpoint=endpoint,
        )
        return parse_response(
            await self._request(spec), expected_keys=spec.expected_keys
        )

    async def update(
        self,
        notification_id: str,
        body: str | Message = "",
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
        **options: Unpack[MessageOptions],
    ) -> Response:
        """Replace a notification asynchronously; replacement fields are not merged.

        Args:
            notification_id: ID used in the original notification.
            body: Replacement text or message.
            device_key: Single-recipient override.
            device_keys: Optional batch recipients.
            **options: Other replacement notification fields.

        Returns:
            The server's acceptance response.
        """
        options = _id_options(notification_id, options, delete=False)
        return await self.send(
            body, device_key=device_key, device_keys=device_keys, **options
        )

    async def delete(
        self,
        notification_id: str,
        *,
        device_key: str | None = None,
        device_keys: Sequence[str] | None = None,
    ) -> Response:
        """Request background deletion of a notification asynchronously.

        Args:
            notification_id: Notification to delete.
            device_key: Single-recipient override.
            device_keys: Optional batch recipients.

        Returns:
            Server acceptance; device deletion requires Background App Refresh.
        """
        return await self.send(
            device_key=device_key,
            device_keys=device_keys,
            id=notification_id,
            delete=True,
        )

    async def ping(self) -> Response:
        """Return the validated pong response from ``GET /ping``."""
        return parse_response(
            await self._request(RequestSpec("GET", self._config.url("ping")))
        )

    async def healthz(self) -> str:
        """Return ``ok`` from ``GET /healthz``."""
        return parse_health(
            await self._request(RequestSpec("GET", self._config.url("healthz")))
        )

    async def root(self) -> str:
        """Return ``ok`` from the server's root endpoint."""
        return parse_health(
            await self._request(RequestSpec("GET", self._config.url("")))
        )

    async def info(self) -> ServerInfo:
        """Return typed version and platform information from ``GET /info``."""
        return parse_info(
            await self._request(RequestSpec("GET", self._config.url("info")))
        )

    async def register(
        self, device_token: str, *, device_key: str | None = None
    ) -> Registration:
        """Register an APNs token asynchronously.

        Args:
            device_token: APNs token obtained from the Bark app.
            device_key: Explicit existing/custom key; omitted requests a new key.

        Returns:
            Registered credentials, without changing this client.
        """
        return parse_registration(
            await self._request(
                registration_request(self._config, device_token, device_key)
            )
        )

    async def check_device(self, device_key: str | None = None) -> Response:
        """Check a device registration asynchronously.

        Args:
            device_key: Optional override of the client's device key.

        Returns:
            A successful response, or raises for an unregistered key.
        """
        return parse_response(
            await self._request(check_request(self._config, device_key))
        )

    async def _request(self, spec: RequestSpec) -> httpx2.Response:
        self._ensure_open()
        try:
            return await self._http.send(
                self._build_request(spec), follow_redirects=False
            )
        except httpx2.RequestError as error:
            message = f"Baark HTTP request failed ({type(error).__name__})."
            raise TransportError(message) from None

    async def aclose(self) -> None:
        """Close this SDK client and its HTTP pool if owned; safe to repeat."""
        if not self._closed and self._owns_client:
            await self._http.aclose()
        self._closed = True

    async def __aenter__(self) -> Self:
        """Enter an open async client context."""
        self._ensure_open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the owned async pool on context exit."""
        await self.aclose()


def _id_options(
    notification_id: str, options: MessageOptions, *, delete: bool
) -> MessageOptions:
    if not isinstance(notification_id, str) or not notification_id:
        invalid("notification_id must be a non-empty string.")
    if "id" in options and options["id"] != notification_id:
        invalid("The notification id conflicts with the id option.")
    if "delete" in options and options["delete"] != delete:
        invalid("The delete option conflicts with this operation.")
    return {**options, "id": notification_id, "delete": delete}


def send(  # noqa: PLR0913 - One-shot convenience exposes client settings.
    body: str | Message = "",
    *,
    device_key: str | None = None,
    device_keys: Sequence[str] | None = None,
    server_url: str | None = None,
    encryption: Encryption | None = None,
    timeout: float | httpx2.Timeout | None = 10.0,
    **options: Unpack[MessageOptions],
) -> Response:
    """Send once and close the connection; use Baark for repeated sends.

    Args:
        body: Notification text or message.
        device_key: Device key or URL, unless a batch is supplied.
        device_keys: Batch recipients.
        server_url: Optional custom server URL.
        encryption: Optional payload encryption.
        timeout: HTTP timeout.
        **options: Notification fields.

    Returns:
        The validated server response.
    """
    with Baark(
        device_key, server_url=server_url, encryption=encryption, timeout=timeout
    ) as client:
        return client.send(body, device_keys=device_keys, **options)


async def async_send(  # noqa: PLR0913 - Matches the synchronous helper.
    body: str | Message = "",
    *,
    device_key: str | None = None,
    device_keys: Sequence[str] | None = None,
    server_url: str | None = None,
    encryption: Encryption | None = None,
    timeout: float | httpx2.Timeout | None = 10.0,  # noqa: ASYNC109 - HTTP timeout.
    **options: Unpack[MessageOptions],
) -> Response:
    """Send once asynchronously and close the connection.

    Args:
        body: Notification text or message.
        device_key: Device key or URL, unless a batch is supplied.
        device_keys: Batch recipients.
        server_url: Optional custom server URL.
        encryption: Optional payload encryption.
        timeout: HTTP timeout.
        **options: Notification fields.

    Returns:
        The validated server response.
    """
    async with AsyncBaark(
        device_key, server_url=server_url, encryption=encryption, timeout=timeout
    ) as client:
        return await client.send(body, device_keys=device_keys, **options)
