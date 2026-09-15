# Copyright (c) 2026 doabell.
"""Typed notification options and server responses."""

from __future__ import annotations

import copy
import math
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import StrEnum
from http import HTTPStatus
from typing import Literal, TypedDict, cast

from baark.errors import APIError, APNSReason, BatchError, invalid

type JSONValue = (
    str | int | float | bool | list[JSONValue] | dict[str, JSONValue] | None
)
type LevelValue = Literal["active", "passive", "timeSensitive", "critical"]
type ActionValue = Literal["none", "alert"]
type EndpointValue = Literal["push", "device", "form", "get"]


class Level(StrEnum):
    """iOS interruption levels supported by Bark."""

    ACTIVE = "active"
    PASSIVE = "passive"
    TIME_SENSITIVE = "timeSensitive"
    CRITICAL = "critical"


class Action(StrEnum):
    """Special actions when a notification is tapped."""

    NONE = "none"
    ALERT = "alert"


class Endpoint(StrEnum):
    """Push request formats; ``PUSH`` is the default JSON API."""

    PUSH = "push"
    DEVICE = "device"
    FORM = "form"
    GET = "get"


class Sound(StrEnum):
    """Bundled Bark sounds; custom sound names are also accepted."""

    ALARM = "alarm"
    ANTICIPATE = "anticipate"
    BELL = "bell"
    BIRDSONG = "birdsong"
    BLOOM = "bloom"
    CALYPSO = "calypso"
    CHIME = "chime"
    CHOO = "choo"
    DESCENT = "descent"
    ELECTRONIC = "electronic"
    FANFARE = "fanfare"
    GLASS = "glass"
    GO_TO_SLEEP = "gotosleep"
    HEALTH_NOTIFICATION = "healthnotification"
    HORN = "horn"
    LADDER = "ladder"
    MAIL_SENT = "mailsent"
    MINUET = "minuet"
    MULTIWAY_INVITATION = "multiwayinvitation"
    NEW_MAIL = "newmail"
    NEWSFLASH = "newsflash"
    NOIR = "noir"
    PAYMENT_SUCCESS = "paymentsuccess"
    SHAKE = "shake"
    SHERWOOD_FOREST = "sherwoodforest"
    SILENCE = "silence"
    SPELL = "spell"
    SUSPENSE = "suspense"
    TELEGRAPH = "telegraph"
    TIPTOES = "tiptoes"
    TYPEWRITERS = "typewriters"
    UPDATE = "update"


class MessageOptions(TypedDict, total=False):
    """Keyword options for messages, client defaults, and send helpers.

    ``None`` removes an inherited default. Boolean options are serialized to
    Bark's ``"1"``/``"0"`` flags. ``logo`` is an alias for ``icon``.
    See ``Message`` and the README for the complete field reference.
    """

    title: str | None
    subtitle: str | None
    markdown: str | None
    level: Level | LevelValue | None
    volume: float | None
    badge: int | None
    call: bool | None
    auto_copy: bool | None
    copy: str | None
    sound: Sound | str | None
    icon: str | None
    logo: str | None
    image: str | None
    group: str | None
    archive: bool | None
    ttl: int | None
    url: str | None
    action: Action | ActionValue | None
    id: str | None
    delete: bool | None
    ciphertext: str | None
    iv: str | None
    extra: Mapping[str, JSONValue] | None


_TEXT_FIELDS = (
    "body",
    "title",
    "subtitle",
    "markdown",
    "copy",
    "sound",
    "icon",
    "logo",
    "image",
    "group",
    "url",
    "id",
    "ciphertext",
    "iv",
)
_BOOL_FIELDS = ("call", "auto_copy", "archive", "delete")
_WIRE_NAMES = {"auto_copy": "autoCopy", "archive": "isArchive", "logo": "icon"}
_MAX_COLLAPSE_ID_BYTES = 64
_MAX_VOLUME = 10


def normalize_options(options: MessageOptions) -> MessageOptions:
    """Copy options and resolve the logo alias before merging defaults.

    Args:
        options: Notification keyword arguments.

    Returns:
        An independent mapping with ``logo`` replaced by ``icon``.
    """
    result = options.copy()
    extra = result.get("extra")
    if isinstance(extra, Mapping):
        result["extra"] = dict(extra)
    result = copy.deepcopy(result)
    if "logo" in result:
        logo = result.pop("logo")
        if "icon" in result and result["icon"] != logo:
            invalid("Specify either icon or logo, or give both the same value.")
        result["icon"] = logo
    return result


def validate_json(value: object) -> None:
    """Reject non-JSON values and non-finite numbers in extension fields.

    Args:
        value: Value to validate recursively.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            validate_json(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            validate_json(item)
        return
    invalid("Extension fields must contain finite JSON values and string keys.")


@dataclass(frozen=True, slots=True)
class Message:
    """A reusable notification independent of its recipient.

    Args:
        body: Plain text; may be empty for Markdown or deletion requests.
        title: Notification title.
        subtitle: Secondary title.
        markdown: Markdown content, taking precedence over body on the device.
        level: Interruption level.
        volume: Critical-alert volume from 0 to 10.
        badge: App badge value; zero clears the badge.
        call: Repeat the ringtone for approximately 30 seconds.
        auto_copy: Request automatic clipboard copying where iOS permits it.
        copy: Text for the notification's copy action.
        sound: Bundled or custom ringtone name, with or without ``.caf``.
        icon: Custom notification icon URL.
        logo: Alias for icon.
        image: Attachment image URL.
        group: Notification and history group.
        archive: Override the app's history setting.
        ttl: Archived-message lifetime in seconds.
        url: Link or URL scheme to open on tap.
        action: Special tap action.
        id: Stable notification identifier for updates and deletion.
        delete: Delete the notification identified by id.
        ciphertext: An already encrypted, base64-encoded payload.
        iv: IV accompanying an already encrypted payload.
        extra: Additional server fields; known fields cannot be overridden here.
    """

    body: str = ""
    title: str | None = field(default=None, kw_only=True)
    subtitle: str | None = field(default=None, kw_only=True)
    markdown: str | None = field(default=None, kw_only=True)
    level: Level | LevelValue | None = field(default=None, kw_only=True)
    volume: float | None = field(default=None, kw_only=True)
    badge: int | None = field(default=None, kw_only=True)
    call: bool | None = field(default=None, kw_only=True)
    auto_copy: bool | None = field(default=None, kw_only=True)
    copy: str | None = field(default=None, kw_only=True)
    sound: Sound | str | None = field(default=None, kw_only=True)
    icon: str | None = field(default=None, kw_only=True)
    logo: str | None = field(default=None, kw_only=True)
    image: str | None = field(default=None, kw_only=True)
    group: str | None = field(default=None, kw_only=True)
    archive: bool | None = field(default=None, kw_only=True)
    ttl: int | None = field(default=None, kw_only=True)
    url: str | None = field(default=None, kw_only=True)
    action: Action | ActionValue | None = field(default=None, kw_only=True)
    id: str | None = field(default=None, kw_only=True)
    delete: bool | None = field(default=None, kw_only=True)
    ciphertext: str | None = field(default=None, kw_only=True, repr=False)
    iv: str | None = field(default=None, kw_only=True, repr=False)
    extra: Mapping[str, JSONValue] | None = field(
        default=None, kw_only=True, repr=False
    )

    def __post_init__(self) -> None:
        """Validate the message before it can be sent."""
        self._validate_field_types()
        self._validate_numbers()
        if self.level is not None and self.level not in Level:
            invalid("level must be active, passive, timeSensitive, or critical.")
        if self.action is not None and self.action not in Action:
            invalid("action must be none or alert.")
        if self.id is not None and (
            not self.id or len(self.id.encode()) > _MAX_COLLAPSE_ID_BYTES
        ):
            invalid("id must contain between 1 and 64 UTF-8 bytes.")
        if self.delete and not self.id:
            invalid("delete requires a notification id.")
        if self.iv is not None and self.ciphertext is None:
            invalid("iv requires ciphertext; generated IVs belong to Encryption.")
        object.__setattr__(self, "extra", self.options().get("extra"))

    def _validate_field_types(self) -> None:
        for name in _TEXT_FIELDS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                invalid(f"{name} must be a string.")
        if not isinstance(self.body, str):
            invalid("body must be a string.")
        for name in _BOOL_FIELDS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                invalid(f"{name} must be a boolean.")

    def _validate_numbers(self) -> None:
        for name in ("badge", "ttl"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                invalid(f"{name} must be an integer.")
        if self.ttl is not None and self.ttl < 0:
            invalid("ttl must be non-negative.")
        if self.volume is not None and (
            isinstance(self.volume, bool)
            or not isinstance(self.volume, (int, float))
            or not 0 <= self.volume <= _MAX_VOLUME
        ):
            invalid("volume must be a finite number from 0 to 10.")

    def _validate_extra(self) -> None:
        if self.extra is None:
            return
        if not isinstance(self.extra, Mapping):
            invalid("extra must be a mapping of JSON fields.")
        reserved = {
            _WIRE_NAMES.get(item.name, item.name).lower() for item in fields(self)
        } | {"device_key", "device_keys", "autocopy", "isarchive"}
        for key, value in self.extra.items():
            if not isinstance(key, str) or key.lower() in reserved:
                invalid("extra cannot override known notification or routing fields.")
            validate_json(value)
            # bark-server flattens object-valued extensions into APNs parameters.
            if isinstance(value, dict) and any(
                name.lower() in reserved for name in value
            ):
                invalid(
                    "Object extension fields cannot contain known notification "
                    "or routing fields."
                )

    def options(self) -> MessageOptions:
        """Return populated options suitable for merging with client defaults."""
        self._validate_extra()
        options = cast(
            "MessageOptions",
            {
                item.name: getattr(self, item.name)
                for item in fields(self)
                if item.name != "body" and getattr(self, item.name) is not None
            },
        )
        return normalize_options(options)

    def to_payload(self) -> dict[str, JSONValue]:
        """Serialize using Bark's field names and boolean wire representation."""
        result: dict[str, JSONValue] = {"body": self.body}
        options = self.options()
        extra = options.pop("extra", None)
        for name, value in options.items():
            wire_value = ("1" if value else "0") if isinstance(value, bool) else value
            result[_WIRE_NAMES.get(name, name)] = cast("JSONValue", wire_value)
        if extra:
            result.update(extra)
        return result


@dataclass(frozen=True, slots=True)
class Delivery:
    """One recipient's result from a server-side batch."""

    device_key: str = field(repr=False)
    code: int
    message: str = field(default="", repr=False)

    @property
    def ok(self) -> bool:
        """Whether the server accepted this recipient's notification."""
        return self.code == HTTPStatus.OK

    @property
    def apns_reason(self) -> APNSReason | None:
        """Recognized APNs rejection; None for success or unrecognized errors."""
        return None if self.ok else APNSReason.from_message(self.message)


@dataclass(frozen=True, slots=True)
class Response:
    """A validated Bark response; acceptance does not confirm device display."""

    code: int
    message: str
    timestamp: int | None = None
    data: JSONValue = field(default=None, repr=False)
    deliveries: tuple[Delivery, ...] = ()
    status_code: int = HTTPStatus.OK

    @property
    def ok(self) -> bool:
        """Whether the request and every reported recipient succeeded."""
        return (
            HTTPStatus.OK <= self.status_code < HTTPStatus.MULTIPLE_CHOICES
            and self.code == HTTPStatus.OK
            and not self.failures
        )

    @property
    def failures(self) -> tuple[Delivery, ...]:
        """Recipients the server rejected, in response order."""
        return tuple(item for item in self.deliveries if not item.ok)

    def raise_for_status(self) -> None:
        """Raise an APIError or BatchError for an unsuccessful result."""
        if (
            not HTTPStatus.OK <= self.status_code < HTTPStatus.MULTIPLE_CHOICES
            or self.code != HTTPStatus.OK
        ):
            raise APIError(
                status_code=self.status_code,
                code=self.code,
                server_message=self.message,
            )
        if self.failures:
            raise BatchError(self)


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """Version and platform information returned by ``/info``."""

    version: str
    build: str
    arch: str
    commit: str
    devices: int


@dataclass(frozen=True, slots=True)
class Registration:
    """A server's mapping between a Bark key and an APNs device token."""

    device_key: str = field(repr=False)
    device_token: str = field(repr=False)
