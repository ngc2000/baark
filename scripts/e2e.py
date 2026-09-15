# Copyright (c) 2026 doabell.
"""Run an opt-in live Bark smoke test using environment configuration.

Run from the checkout with ``uv run --env-file .env python scripts/e2e.py``.
The default action sends one basic notification through each client. Use
``--list-cases`` for optional visual checks. Confirm delivery on the phone before
using ``--action update`` or ``--action delete`` with the same cases.
"""

import argparse
import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from baark import (
    Action,
    APIError,
    APNSReason,
    AsyncBaark,
    Baark,
    BaarkError,
    Message,
    MessageOptions,
    Sound,
)

_LOGO_URL = "https://day.app/assets/images/avatar.jpg"
_IMAGE_URL = (
    "https://raw.githubusercontent.com/Finb/Bark/"
    "2a35a5b990415eada5fcc6c95deb9850c239796a/docs/_media/example.jpg"
)


@dataclass(frozen=True)
class _Case:
    name: str
    expectation: str
    options: MessageOptions


def _cases(logo_url: str, image_url: str) -> tuple[_Case, ...]:
    return (
        _Case("basic", "Readable text and UTC timestamp; grouped under baark-e2e.", {}),
        _Case(
            "logo",
            "Custom avatar beside the notification (iOS 15+); subtitle visible.",
            {"logo": logo_url, "subtitle": "Custom logo test"},
        ),
        _Case(
            "image",
            "Long-press the notification to see the attached image.",
            {"image": image_url},
        ),
        _Case(
            "markdown",
            "Formatted heading, bold text, list and code in Bark's history/detail.",
            {"markdown": "# Markdown test\n**Bold text**\n\n- List item\n- `code`"},
        ),
        _Case(
            "link",
            "Tap the notification to open Bark's documentation website.",
            {"url": "https://bark.day.app/"},
        ),
        _Case(
            "copy",
            "Long-press/use Copy, then paste BAARK-E2E-COPY; tap for action popup.",
            {"copy": "BAARK-E2E-COPY", "auto_copy": True, "action": Action.ALERT},
        ),
        _Case(
            "sound",
            "Hear the bell sound, subject to your iOS sound/Focus settings.",
            {"sound": Sound.BELL},
        ),
        _Case(
            "history",
            "Find this message in Bark's baark-e2e history group.",
            {"archive": True},
        ),
        _Case(
            "ephemeral",
            "Visible in Notification Center, absent from Bark history.",
            {"archive": False},
        ),
    )


def _notification_id(case: _Case, client: str) -> str:
    suffix = "" if case.name == "basic" else f"-{case.name}"
    return f"baark-e2e-{client}{suffix}"


def _message(case: _Case, client: str, action: str) -> Message:
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    title = f"baark E2E: {client}"
    if case.name != "basic":
        title += f" / {case.name}"
    options: MessageOptions = {"title": title, "group": "baark-e2e", "archive": True}
    options.update(case.options)
    verb = "Updated" if action == "update" else "Sent"
    marker = f"{verb} through the {client} client at {timestamp}."
    if options.get("markdown"):
        options["markdown"] = f"{options['markdown']}\n\n{marker}"
    return Message(f"{marker}\n{case.expectation}", **options)


def _report(action: str, case: _Case, client: str) -> None:
    # Report only the action and public test ID, never credentials or responses.
    expectation = case.expectation
    if action == "delete":
        expectation = (
            "Entry should disappear from Notification Center and Bark history."
        )
    elif action == "update":
        expectation = f"Same entry shows Updated and a new timestamp. {expectation}"
    print(  # noqa: T201 - Interactive smoke-test output.
        f"Server accepted {action}: {_notification_id(case, client)}.\n"
        f"  Check on phone: {expectation}"
    )


def _run_sync(action: str, cases: tuple[_Case, ...]) -> None:
    with Baark.from_env() as client:
        for case in cases:
            notification_id = _notification_id(case, "sync")
            if action == "send":
                client.send(_message(case, "sync", action), id=notification_id)
            elif action == "update":
                client.update(notification_id, _message(case, "sync", action))
            else:
                client.delete(notification_id)
            _report(action, case, "sync")


async def _run_async(action: str, cases: tuple[_Case, ...]) -> None:
    async with AsyncBaark.from_env() as client:
        for case in cases:
            notification_id = _notification_id(case, "async")
            if action == "send":
                await client.send(_message(case, "async", action), id=notification_id)
            elif action == "update":
                await client.update(notification_id, _message(case, "async", action))
            else:
                await client.delete(notification_id)
            _report(action, case, "async")


def _selected_cases(args: argparse.Namespace) -> tuple[_Case, ...]:
    cases = _cases(
        args.logo_url or os.environ.get("BAARK_E2E_LOGO_URL", _LOGO_URL),
        args.image_url or os.environ.get("BAARK_E2E_IMAGE_URL", _IMAGE_URL),
    )
    selected = tuple(
        case for case in cases if "all" in args.case or case.name in args.case
    )
    # Reject unusable media URLs before sending any notification in the selection.
    # Delete needs only the IDs and works even if an old media URL is unavailable.
    if args.action != "delete":
        for case in selected:
            for field in ("logo", "image"):
                value = case.options.get(field)
                if isinstance(value, str):
                    _validate_media_url(value, field)
    return selected


def _validate_media_url(value: str, field: str) -> None:
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        valid = False
    if not valid:
        message = f"The {field} URL must be an absolute HTTP(S) image URL."
        raise ValueError(message)


def _parser() -> argparse.ArgumentParser:
    cases = _cases(_LOGO_URL, _IMAGE_URL)
    parser = argparse.ArgumentParser(
        description="Send, update, or delete real Bark test notifications.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--case",
        choices=(*(case.name for case in cases), "all"),
        nargs="+",
        action="extend",
        help="Cases to run; default: basic. all sends nine messages per client.",
    )
    parser.add_argument(
        "--list-cases", action="store_true", help="List phone checks without sending."
    )
    parser.add_argument(
        "--logo-url", help="Override BAARK_E2E_LOGO_URL or demo avatar."
    )
    parser.add_argument(
        "--image-url", help="Override BAARK_E2E_IMAGE_URL or demo screenshot."
    )
    parser.add_argument(
        "--action",
        choices=("send", "update", "delete"),
        default="send",
        help="Create, replace, or request deletion of the selected test IDs.",
    )
    parser.add_argument(
        "--client",
        choices=("sync", "async", "both"),
        default="both",
        help="Use blocking calls, awaitable calls, or sync followed by async.",
    )
    parser.add_argument(
        "--show-server-message",
        action="store_true",
        help="Show raw API error details locally; these may contain credentials.",
    )
    return parser


def _error_detail(error: BaarkError, *, show_server_message: bool) -> str:
    detail = f"{type(error).__name__}: {error}\n"
    if isinstance(error, APIError):
        if error.apns_reason in {
            APNSReason.BAD_DEVICE_TOKEN,
            APNSReason.EXPIRED_TOKEN,
            APNSReason.UNREGISTERED,
        }:
            detail += (
                "Refresh this server's device registration in the Bark app "
                "and verify the APNs environment before retrying.\n"
            )
        if show_server_message:
            detail += f"Server message: {error.server_message!r}\n"
        else:
            detail += (
                "Use --show-server-message to inspect API error details locally.\n"
            )
    return detail


def main(argv: list[str] | None = None) -> None:
    """Run the requested live checks, reporting SDK errors without tracebacks.

    Args:
        argv: Optional command-line arguments, excluding the program name.
    """
    parser = _parser()
    args = parser.parse_args(argv)
    if args.list_cases:
        for case in _cases(_LOGO_URL, _IMAGE_URL):
            print(f"{case.name}: {case.expectation}")  # noqa: T201 - Case checklist.
        return
    args.case = args.case or ["basic"]
    try:
        cases = _selected_cases(args)
    except ValueError as error:
        parser.error(str(error))
    key = os.environ.get("BAARK_DEVICE_KEY", "")
    if not key or key.rstrip("/").rsplit("/", 1)[-1] == "YOUR_DEVICE_KEY":
        parser.error(
            "Set BAARK_DEVICE_KEY in .env, then run with uv run --env-file .env."
        )
    try:
        if args.action == "delete":
            print(  # noqa: T201 - Phone setup for a live check.
                "Deletion requires Background App Refresh and may be delayed by iOS."
            )
        if args.client in {"sync", "both"}:
            _run_sync(args.action, cases)
        if args.client in {"async", "both"}:
            asyncio.run(_run_async(args.action, cases))
    except BaarkError as error:
        parser.exit(
            1, _error_detail(error, show_server_message=args.show_server_message)
        )


if __name__ == "__main__":
    main()
