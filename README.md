# baark

A typed Python SDK for [Bark](https://bark.day.app/) push notifications. Matching
sync and async clients, connection pooling, rich notifications, and optional AES
encryption. Requires Python 3.13+; built on `httpx2` and PyCryptodome.

## Install

From PyPI:

```sh
uv add baark
```

## Quick start

Copy your device key from Bark. A URL ending in the key also works.

```python
from baark import Baark

with Baark("YOUR_DEVICE_KEY", group="backups") as client:
    result = client.send(
        "The backup finished.",
        title="Backup",
        logo="https://example.com/backup.png",
        url="https://example.com/backups/latest",
    )
    print(result.ok)
```

Reuse the client for repeated sends; the context manager closes its connections.
`result.ok` confirms server acceptance, not delivery to the phone. For a single
send, use `baark.send("Hello", device_key="YOUR_DEVICE_KEY")`.

### Async

```python
import asyncio

from baark import AsyncBaark


async def main() -> None:
    async with AsyncBaark("YOUR_DEVICE_KEY") as client:
        await client.send("Job finished", title="Build")


asyncio.run(main())
```

Both clients have the same options and operations; await async network calls.
The one-shot async helper is `baark.async_send()`.

### Notification options

Pass options to `send()`, store them in a `Message`, or set client defaults.
Per-call options override message fields, which override client defaults.
Pass `None` in a call to clear an inherited option.

| Purpose | Options |
| --- | --- |
| Content | `body`, `title`, `subtitle`, `markdown` |
| Media | `icon` / `logo` (aliases), `image`, `sound` |
| Attention | `level`, `volume`, `badge`, `call` |
| Interaction | `url`, `action`, `copy`, `auto_copy` |
| History | `group`, `archive`, `ttl` |
| Lifecycle | `id`, `delete` |

Use Python booleans for flags. Media URLs must be reachable by the phone.
See [message types](https://github.com/ngc2000/baark/blob/main/src/baark/models.py) for all options and
[Bark's field reference](https://github.com/Finb/Bark/blob/master/docs/en-us/tutorial.md)
for device behavior.

### Update and delete

```python
with Baark("YOUR_DEVICE_KEY") as client:
    client.send("Downloading…", id="download-42")
    client.update("download-42", "Complete")
    client.delete("download-42")
```

Updates replace the complete message using the same ID. They require Bark 1.5.2+
and bark-server 2.2.5+. Deletion removes the notification and its history entry;
it requires Background App Refresh and may be delayed by iOS.

## Encryption

**Use GCM for new configurations.** It encrypts the message and detects ciphertext
tampering. CBC and ECB are available for compatibility with existing Bark settings.

```python
import os

from baark import Baark, Encryption

settings = Encryption(os.environ["BAARK_ENCRYPTION_KEY"])  # GCM by default
with Baark("YOUR_DEVICE_KEY", encryption=settings) as client:
    client.send("Private content", title="Private title")
```

Use the same key, algorithm, mode, and padding in Bark's **Push Encryption**
settings. Keys are 16, 24, or 32 printable ASCII characters, selecting AES-128,
AES-192, or AES-256. Key size and mode are separate choices: a longer key does
not add tamper detection to CBC or ECB.

| Mode | Protection | IV / nonce in baark | Bark padding | Choose it for |
| --- | --- | --- | --- | --- |
| **GCM** (default) | Encrypts and detects tampering | Fresh 12-character nonce per message | `noPadding` | New setups |
| **CBC** | Encrypts; no tamper detection | Fresh 16-character IV by default | `pkcs7` | Existing CBC setups |
| **ECB** | Encrypts but reveals repeated blocks; no tamper detection | None | `pkcs7` | Legacy compatibility only |

An IV or nonce is a public value used alongside the key. Leave `iv` unset so
baark generates it for each GCM or CBC message; Bark reads it from the request.
Fixed GCM nonces are rejected because reuse breaks its security. Fixed CBC IVs
are supported for compatibility, but reuse leaks repeated message prefixes.
See PyCryptodome's [GCM](https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode)
and [CBC/ECB](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html)
documentation for the underlying modes.

To create settings, run `settings = Encryption.generate()` once, save the key, and enter
`settings.key`, `settings.algorithm`, `settings.mode`, and `settings.padding` in
Bark. It defaults to AES-256-GCM. To import an encoded key, use
`Encryption.from_key(value, encoding="hex")` or `encoding="base64"`; enter the
decoded key in Bark. Hex and base64 are encodings, not encryption methods.

Encryption hides message fields, including titles and media URLs, from the Bark
server. Device routing, IVs, and `id`/`delete` controls remain visible. The key is
never sent. Without this option, HTTPS protects transport but the server can read
notification content.

## Configuration and errors

Set `server_url=` for a custom server. `Baark.from_env()` and
`AsyncBaark.from_env()` read these optional settings from the process environment:

| Variable | Value |
| --- | --- |
| `BAARK_DEVICE_KEY` | Device key or URL ending in the key |
| `BAARK_SERVER_URL` | Custom server URL |
| `BAARK_ENCRYPTION_KEY` | Literal key matching Bark |
| `BAARK_ENCRYPTION_MODE` | `GCM` (default), `CBC`, or `ECB` |
| `BAARK_ENCRYPTION_IV` | Optional fixed CBC IV |

Ordinary constructors do not load these variables or config files. HTTP requests
default to a 10-second timeout, with redirects and retries disabled. Set
`timeout=`, `auth=`, or inject an `httpx2.Client` / `AsyncClient` with `http_client=`
for custom transport settings. Injected clients remain caller-owned; configure
authentication on them.
HTTP query defaults such as authentication tokens are preserved; notification and
routing fields come from baark's arguments and messages.

Send to multiple devices with `client.send("Hello", device_keys=["KEY_A", "KEY_B"])`.
Encrypted batches require all recipients to share encryption settings.
Partial failures raise `BatchError`; inspect `error.response.deliveries` for each
result. All SDK errors inherit from `BaarkError`. `APIError` exposes
`status_code`, `code`, and `apns_reason`; raw `server_message` is available
explicitly and may contain sensitive data.

For alternate endpoints, server utilities, registration, and URL building, see
the [client API](https://github.com/ngc2000/baark/blob/main/src/baark/client.py). Also see
[response and message types](https://github.com/ngc2000/baark/blob/main/src/baark/models.py),
[errors](https://github.com/ngc2000/baark/blob/main/src/baark/errors.py), and
[encryption helpers](https://github.com/ngc2000/baark/blob/main/src/baark/crypto.py).

## Alternatives

| Project | Useful when you want | Documented encryption support |
| --- | --- | --- |
| **baark** | Reusable, typed sync and async Bark clients in Python | GCM, CBC, ECB |
| [iskoldtbark](https://pypi.org/project/iskoldtbark/) | A Bark CLI with saved devices, recipient groups, and per-device keys | AES-256-GCM; AES-128/192/256-CBC |
| [bark-python](https://pypi.org/project/bark-python/) | A small client with replaceable encryption strategies | Built-in CBC and ECB; custom strategies |
| [Apprise](https://appriseit.com/) | One library or CLI for Bark and other notification services | [Bark AES-GCM](https://appriseit.com/services/bark/#encryption) |

For simple scripts, [Bark's HTTP API](https://github.com/Finb/Bark/blob/master/docs/en-us/tutorial.md)
also works directly with curl or your existing HTTP client.

## Development

Install [uv](https://docs.astral.sh/uv/), [just](https://just.systems/), and
[actionlint](https://github.com/rhysd/actionlint), then run `uv sync --locked`.
Windows development also needs Bash, as provided by Git for Windows.

### Test with your phone

Copy `.env.example` with `cp -n .env.example .env`, then edit `.env` with your
device key and optional encryption settings. Leave unused settings commented out.

```sh
uv run python scripts/e2e.py --list-cases
uv run --env-file .env python scripts/e2e.py --client sync --case logo image markdown
```

These selected cases send three real notifications. Check the phone, then repeat
with the same client and cases plus `--action update` or `--action delete`.
`--case all` covers nine cases; the default client selection, `both`, doubles
the count. Use `--help` for media URL overrides and other options.

### Offline checks

```sh
just check
just build
just test-wheel
```

The test suite uses mock HTTP transports and encryption vectors. Coverage checks
enforce the threshold in `pyproject.toml`. CI tests the built wheel on Python 3.13
and 3.14 across Linux, macOS, and Windows.

## License

[MIT](https://github.com/ngc2000/baark/blob/main/LICENSE).
