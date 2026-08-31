"""Controlled HTTPS connector for v1.18 scheduled HTTP GET execution.

The connector deliberately does not use a general-purpose HTTP client.  It
resolves every attempt afresh, rejects the complete DNS answer set when any
answer is outside the fixed public-address policy, connects to one numeric
peer, and retains the canonical hostname for TLS SNI, certificate validation,
and the HTTP ``Host`` header.  Responses are parsed with byte limits while
they are read; response bodies, URLs, and underlying exception text never
cross the finite public error boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import idna


HEADER_LIMIT_BYTES = 32 * 1024
MANIFEST_BODY_LIMIT_BYTES = 32 * 1024
TARGET_USER_AGENT = "LN-Church-Scheduled-GET/1.0"
MANIFEST_USER_AGENT = "LN-Church-Scheduled-Manifest/1.0"


class FetchScope(str, Enum):
    """The only network scopes owned by the private v1.18 SDK."""

    MANIFEST_RELEASE = "OFFICIAL_SDK_MANIFEST_RELEASE"
    TARGET = "OFFICIAL_SDK_TARGET"


class NetworkFetchError(Exception):
    """Finite, URL-free connector failure."""

    _CODES = frozenset(
        {
            "dns_error",
            "policy_rejected",
            "tls_error",
            "connection_error",
            "timeout",
            "protocol_error",
            "response_too_large",
            "encoding_unsupported",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "protocol_error"
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FetchTimeouts:
    connect_seconds: float
    response_head_seconds: float
    total_seconds: float

    def __post_init__(self) -> None:
        for value in (
            self.connect_seconds,
            self.response_head_seconds,
            self.total_seconds,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0.0
            ):
                raise ValueError("Invalid fetch timeout.")
        if self.connect_seconds > self.total_seconds:
            raise ValueError("Invalid fetch timeout.")
        if self.response_head_seconds > self.total_seconds:
            raise ValueError("Invalid fetch timeout.")


MANIFEST_TIMEOUTS = FetchTimeouts(0.5, 1.2, 1.5)
TARGET_TIMEOUTS = FetchTimeouts(3.0, 10.0, 12.0)


@dataclass(frozen=True)
class FetchResponse:
    """A bounded response projection; target responses always have no body."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes = b""
    peer_address: Optional[str] = None


class CanonicalHTTPSURL:
    """Public-safe projection over private, slotted wire-only URL state.

    A signed Manifest query is a credential.  It is therefore deliberately
    absent from dataclass fields, ``__dict__``, repr/str, and pickle.  The raw
    request-target is available only through the explicit connector-facing
    accessor.
    """

    __slots__ = ("__hostname", "__request_target")

    def __init__(self, hostname: str, request_target: str) -> None:
        object.__setattr__(self, "_CanonicalHTTPSURL__hostname", hostname)
        object.__setattr__(
            self, "_CanonicalHTTPSURL__request_target", request_target
        )

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise AttributeError("Canonical HTTPS URL state is immutable.")

    @property
    def hostname(self) -> str:
        return self.__hostname

    def transport_request_target(self) -> str:
        """Return the byte-preserved request-target for controlled transport."""

        return self.__request_target

    def __repr__(self) -> str:
        return "CanonicalHTTPSURL(hostname=%r, request_target=<redacted>)" % (
            self.__hostname,
        )

    def __str__(self) -> str:
        return "https://%s/<redacted>" % self.__hostname

    def __reduce_ex__(self, _protocol: int) -> Any:
        raise TypeError("Canonical HTTPS URL transport state is not serializable.")


_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
    ".private",
    ".home",
)
_FORBIDDEN_HOSTS = frozenset(
    {
        "localhost",
        "local",
        "internal",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

# IPv6 policy is compiled from two pinned IANA XML snapshots and performs no
# registry/network access at runtime.  Snapshot provenance:
#
# Global Unicast registry
#   URL: https://www.iana.org/assignments/ipv6-unicast-address-assignments/
#        ipv6-unicast-address-assignments.xml
#   Last Updated: 2025-10-10
#   Input format: IANA XML
#   Raw SHA-256: 22f9a545e020ea6b9adea9ea0276f3157e32c838682459a45bfe7760de0aefc3
# Special-Purpose registry
#   URL: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml
#   Last Updated: 2025-10-09
#   Input format: IANA XML
#   Raw SHA-256: c17f4380ba84fb2160dae82ebfd8bd155a5853cfab624ed3a9fd251638a8be02
#
# The normalized table is ASCII lines, final LF, sorted by numeric prefix then
# prefix length within each registry.  Global lines are
# ``GLOBAL|prefix|ALLOCATED`` and special lines are
# ``SPECIAL|prefix|Destination|Forwardable|Globally-Reachable|Reserved``.
# Its SHA-256 is 054b2bc053c771aedc1050f37a70176c4a2a8dc06f430453192d47890b2aba76.
#
# IPv4 retains the explicit v1.18 table below.  No IPv6 decision delegates to
# ``ipaddress.is_global`` because its classifications vary by Python release.
IANA_IPV6_SNAPSHOT_PROVENANCE = (
    (
        "global_unicast_registry_url",
        "https://www.iana.org/assignments/ipv6-unicast-address-assignments/"
        "ipv6-unicast-address-assignments.xml",
    ),
    ("global_unicast_last_updated", "2025-10-10"),
    ("global_unicast_input_format", "IANA XML"),
    (
        "global_unicast_raw_sha256",
        "22f9a545e020ea6b9adea9ea0276f3157e32c838682459a45bfe7760de0aefc3",
    ),
    (
        "special_purpose_registry_url",
        "https://www.iana.org/assignments/iana-ipv6-special-registry/"
        "iana-ipv6-special-registry.xml",
    ),
    ("special_purpose_last_updated", "2025-10-09"),
    ("special_purpose_input_format", "IANA XML"),
    (
        "special_purpose_raw_sha256",
        "c17f4380ba84fb2160dae82ebfd8bd155a5853cfab624ed3a9fd251638a8be02",
    ),
    (
        "normalized_prefix_table_sha256",
        "054b2bc053c771aedc1050f37a70176c4a2a8dc06f430453192d47890b2aba76",
    ),
)

_REJECTED_V4 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_V4_GLOBAL_EXCEPTIONS = frozenset(
    {ipaddress.ip_address("192.0.0.9"), ipaddress.ip_address("192.0.0.10")}
)
_IANA_V6_ALLOCATED_GLOBAL_UNICAST = tuple(
    ipaddress.ip_network(value)
    for value in (
        "2001::/23",
        "2001:200::/23",
        "2001:400::/23",
        "2001:600::/23",
        "2001:800::/22",
        "2001:c00::/23",
        "2001:e00::/23",
        "2001:1200::/23",
        "2001:1400::/22",
        "2001:1800::/23",
        "2001:1a00::/23",
        "2001:1c00::/22",
        "2001:2000::/19",
        "2001:4000::/23",
        "2001:4200::/23",
        "2001:4400::/23",
        "2001:4600::/23",
        "2001:4800::/23",
        "2001:4a00::/23",
        "2001:4c00::/23",
        "2001:5000::/20",
        "2001:8000::/19",
        "2001:a000::/20",
        "2001:b000::/20",
        "2002::/16",
        "2003::/18",
        "2400::/12",
        "2410::/12",
        "2600::/12",
        "2610::/23",
        "2620::/23",
        "2630::/12",
        "2800::/12",
        "2a00::/12",
        "2a10::/12",
        "2c00::/12",
    )
)

# Each special-purpose row is (prefix, Destination, Forwardable,
# Globally-Reachable, Reserved-by-Protocol).  Empty/N/A snapshot values are
# represented as False, which is the required fail-closed interpretation.
_IANA_V6_SPECIAL_PURPOSE_SNAPSHOT_ROWS = (
    ("::/128", "False", "False", "False", "True"),
    ("::1/128", "False", "False", "False", "True"),
    ("::ffff:0.0.0.0/96", "False", "False", "False", "True"),
    ("64:ff9b::/96", "True", "True", "True", "False"),
    ("64:ff9b:1::/48", "True", "True", "False", "False"),
    ("100::/64", "True", "True", "False", "False"),
    ("100:0:0:1::/64", "False", "False", "False", "False"),
    ("2001::/23", "False", "False", "False", "False"),
    ("2001::/32", "True", "True", "N/A", "False"),
    ("2001:1::1/128", "True", "True", "True", "False"),
    ("2001:1::2/128", "True", "True", "True", "False"),
    ("2001:1::3/128", "True", "True", "True", "False"),
    ("2001:2::/48", "True", "True", "False", "False"),
    ("2001:3::/32", "True", "True", "True", "False"),
    ("2001:4:112::/48", "True", "True", "True", "False"),
    ("2001:10::/28", "", "", "", ""),
    ("2001:20::/28", "True", "True", "True", "False"),
    ("2001:30::/28", "True", "True", "True", "False"),
    ("2001:db8::/32", "False", "False", "False", "False"),
    ("2002::/16", "True", "True", "N/A", "False"),
    ("2620:4f:8000::/48", "True", "True", "True", "False"),
    ("3fff::/20", "False", "False", "False", "False"),
    ("5f00::/16", "True", "True", "False", "False"),
    ("fc00::/7", "True", "True", "False", "False"),
    ("fe80::/10", "True", "False", "False", "True"),
)
_IANA_V6_SPECIAL_PURPOSE = tuple(
    (
        ipaddress.ip_network(prefix),
        destination == "True",
        forwardable == "True",
        globally_reachable == "True",
        reserved_by_protocol == "True",
    )
    for (
        prefix,
        destination,
        forwardable,
        globally_reachable,
        reserved_by_protocol,
    ) in _IANA_V6_SPECIAL_PURPOSE_SNAPSHOT_ROWS
)
_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "192.0.0.192",
        "168.63.129.16",
        "fd00:ec2::254",
    }
)


def _address_is_allowed(raw: Any) -> bool:
    """Return the deterministic v1.18 public-unicast decision."""

    if not isinstance(raw, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return False
    if "%" in str(raw):
        return False
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if address.compressed.lower() in _METADATA_ADDRESSES:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        if address in _V4_GLOBAL_EXCEPTIONS:
            return True
        return not any(address in network for network in _REJECTED_V4)
    # Explicitly reject transition/mapping address forms before registry
    # membership, even where a Special-Purpose row has permissive flags.
    if address.ipv4_mapped is not None or address.sixtofour is not None:
        return False
    if address.teredo is not None:
        return False
    if not any(
        address in network for network in _IANA_V6_ALLOCATED_GLOBAL_UNICAST
    ):
        return False
    matches = tuple(
        entry for entry in _IANA_V6_SPECIAL_PURPOSE if address in entry[0]
    )
    if not matches:
        return True
    # A more-specific Special-Purpose allocation overrides a containing row
    # such as 2001::/23.  The longest match must satisfy every reachability
    # flag; unknown/N/A/empty values were normalized to False above.
    _, destination, forwardable, globally_reachable, reserved = max(
        matches, key=lambda entry: entry[0].prefixlen
    )
    return bool(
        destination and forwardable and globally_reachable and not reserved
    )


def _canonical_https_url(
    raw_url: Any, *, maximum_utf8_bytes: int = 2048
) -> CanonicalHTTPSURL:
    """Validate an already-canonical ASCII HTTPS URL without rewriting it."""

    if (
        type(raw_url) is not str
        or not raw_url
        or not raw_url.isascii()
        or len(raw_url.encode("utf-8")) > maximum_utf8_bytes
    ):
        raise NetworkFetchError("policy_rejected")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in raw_url):
        raise NetworkFetchError("policy_rejected")
    if "\\" in raw_url or _PERCENT_RE.search(raw_url):
        raise NetworkFetchError("policy_rejected")
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise NetworkFetchError("policy_rejected") from None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
        or parsed.hostname is None
    ):
        raise NetworkFetchError("policy_rejected")
    # WHATWG serialization removes an explicit default port and inserts '/'.
    # Reject such non-canonical spellings rather than silently normalizing.
    if port == 443 or not parsed.path.startswith("/"):
        raise NetworkFetchError("policy_rejected")
    host = parsed.hostname
    if ":" in host:  # IP literals, including bracketed IPv6, are forbidden.
        raise NetworkFetchError("policy_rejected")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise NetworkFetchError("policy_rejected")
    try:
        canonical_host = idna.encode(host, uts46=False).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        raise NetworkFetchError("policy_rejected") from None
    if host != canonical_host or parsed.netloc != canonical_host:
        raise NetworkFetchError("policy_rejected")
    if canonical_host in _FORBIDDEN_HOSTS or canonical_host.endswith(
        _FORBIDDEN_HOST_SUFFIXES
    ):
        raise NetworkFetchError("policy_rejected")
    # Dot segments and their simple percent-encoded forms are not canonical.
    for segment in parsed.path.split("/"):
        lowered = segment.lower()
        if lowered in {".", "..", "%2e", "%2e%2e", ".%2e", "%2e."}:
            raise NetworkFetchError("policy_rejected")
    request_target = parsed.path
    if parsed.query:
        request_target += "?" + parsed.query
    return CanonicalHTTPSURL(canonical_host, request_target)


def _system_resolver(host: str, port: int) -> Tuple[str, ...]:
    records = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return tuple(str(record[4][0]) for record in records)


def _resolve_public_addresses(
    host: str,
    *,
    resolver: Callable[[str, int], Sequence[str]] = _system_resolver,
    timeout: float,
) -> Tuple[str, ...]:
    """Resolve once and reject the whole answer set on any invalid answer."""

    result_queue: "queue.Queue[Tuple[bool, Any]]" = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result_queue.put((True, resolver(host, 443)))
        except BaseException as error:  # detached below
            result_queue.put((False, error))

    worker = threading.Thread(target=run, name="ln-church-v18-dns", daemon=True)
    worker.start()
    worker.join(max(0.0, float(timeout)))
    if worker.is_alive():
        raise NetworkFetchError("timeout")
    try:
        succeeded, value = result_queue.get_nowait()
    except queue.Empty:
        raise NetworkFetchError("dns_error") from None
    if not succeeded:
        raise NetworkFetchError("dns_error") from None
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise NetworkFetchError("dns_error")
    normalized = []
    for item in value:
        if type(item) is not str or not _address_is_allowed(item):
            raise NetworkFetchError("policy_rejected")
        normalized.append(ipaddress.ip_address(item).compressed.lower())
    unique = tuple(sorted(set(normalized)))
    if not unique:
        raise NetworkFetchError("dns_error")
    return unique


def _remaining(deadline: float, monotonic: Callable[[], float]) -> float:
    value = deadline - monotonic()
    if value <= 0.0:
        raise NetworkFetchError("timeout")
    return value


def _set_timeout(
    stream: socket.socket,
    seconds: float,
    deadline: float,
    monotonic: Callable[[], float],
) -> None:
    stream.settimeout(min(float(seconds), _remaining(deadline, monotonic)))


def _sockaddr(address: str) -> Tuple[int, Tuple[Any, ...]]:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return socket.AF_INET, (address, 443)
    return socket.AF_INET6, (address, 443, 0, 0)


def _same_peer(expected: str, peer: Any) -> bool:
    try:
        return ipaddress.ip_address(peer[0]) == ipaddress.ip_address(expected)
    except (ValueError, TypeError, IndexError):
        return False


class _BufferedSocket:
    def __init__(
        self,
        stream: ssl.SSLSocket,
        *,
        deadline: float,
        head_deadline: float,
        monotonic: Callable[[], float],
    ) -> None:
        self.stream = stream
        self.deadline = deadline
        self.head_deadline = min(deadline, head_deadline)
        self.monotonic = monotonic
        self.buffer = bytearray()

    def _recv(self, maximum: int, *, head: bool = False) -> bytes:
        deadline = self.head_deadline if head else self.deadline
        remaining = _remaining(deadline, self.monotonic)
        self.stream.settimeout(remaining)
        try:
            return self.stream.recv(maximum)
        except socket.timeout:
            raise NetworkFetchError("timeout") from None
        except ssl.SSLError:
            raise NetworkFetchError("protocol_error") from None
        except OSError:
            raise NetworkFetchError("connection_error") from None

    def read_head(self, maximum: int) -> bytes:
        marker = b"\r\n\r\n"
        while True:
            position = self.buffer.find(marker)
            if position >= 0:
                end = position + len(marker)
                if end > maximum:
                    raise NetworkFetchError("response_too_large")
                value = bytes(self.buffer[:end])
                del self.buffer[:end]
                return value
            if len(self.buffer) >= maximum:
                raise NetworkFetchError("response_too_large")
            # Do not read even one body octet for a target response or a
            # non-200 Manifest response.  TLS offers no portable MSG_PEEK, so
            # the bounded head parser deliberately advances one octet at a
            # time until the delimiter is complete.
            chunk = self._recv(1, head=True)
            if not chunk:
                raise NetworkFetchError("protocol_error")
            self.buffer.extend(chunk)
            if len(self.buffer) > maximum:
                raise NetworkFetchError("response_too_large")

    def read_exact(self, size: int) -> bytes:
        result = bytearray()
        if self.buffer:
            take = min(size, len(self.buffer))
            result.extend(self.buffer[:take])
            del self.buffer[:take]
        while len(result) < size:
            chunk = self._recv(min(4096, size - len(result)))
            if not chunk:
                raise NetworkFetchError("protocol_error")
            result.extend(chunk)
        return bytes(result)

    def read_line(self, maximum: int) -> bytes:
        while True:
            position = self.buffer.find(b"\r\n")
            if position >= 0:
                end = position + 2
                if end > maximum:
                    raise NetworkFetchError("response_too_large")
                value = bytes(self.buffer[:end])
                del self.buffer[:end]
                return value
            if len(self.buffer) >= maximum:
                raise NetworkFetchError("response_too_large")
            chunk = self._recv(min(4096, maximum + 1 - len(self.buffer)))
            if not chunk:
                raise NetworkFetchError("protocol_error")
            self.buffer.extend(chunk)

    def read_to_eof(self, maximum: int) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        if len(result) > maximum:
            raise NetworkFetchError("response_too_large")
        while True:
            chunk = self._recv(min(4096, maximum + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > maximum:
                raise NetworkFetchError("response_too_large")


def _parse_response_head(raw: bytes) -> Tuple[int, Dict[str, str]]:
    if not raw.endswith(b"\r\n\r\n"):
        raise NetworkFetchError("protocol_error")
    lines = raw[:-4].split(b"\r\n")
    if not lines:
        raise NetworkFetchError("protocol_error")
    status_parts = lines[0].split(b" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise NetworkFetchError("protocol_error")
    status = int(status_parts[1])
    if not 100 <= status <= 599:
        raise NetworkFetchError("protocol_error")
    selected: Dict[str, str] = {}
    seen = set()
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise NetworkFetchError("protocol_error")
        name, value = line.split(b":", 1)
        if not _HEADER_NAME_RE.fullmatch(name):
            raise NetworkFetchError("protocol_error")
        lowered = name.decode("ascii").lower()
        if b"\x00" in value or b"\r" in value or b"\n" in value:
            raise NetworkFetchError("protocol_error")
        if lowered in {"content-encoding", "content-length", "transfer-encoding"}:
            if lowered in seen:
                raise NetworkFetchError("protocol_error")
            seen.add(lowered)
            try:
                selected[lowered] = value.strip(b" \t").decode("ascii")
            except UnicodeDecodeError:
                raise NetworkFetchError("protocol_error") from None
    return status, selected


def _validate_encoding(headers: Mapping[str, str]) -> None:
    value = headers.get("content-encoding", "").strip().lower()
    if value not in {"", "identity"}:
        raise NetworkFetchError("encoding_unsupported")


def _read_chunked_body(reader: _BufferedSocket, maximum: int) -> bytes:
    result = bytearray()
    trailer_bytes = 0
    while True:
        line = reader.read_line(1024)
        token = line[:-2].split(b";", 1)[0].strip()
        if not token or len(token) > 16:
            raise NetworkFetchError("protocol_error")
        try:
            size = int(token, 16)
        except ValueError:
            raise NetworkFetchError("protocol_error") from None
        if size < 0 or len(result) + size > maximum:
            raise NetworkFetchError("response_too_large")
        if size == 0:
            while True:
                trailer = reader.read_line(HEADER_LIMIT_BYTES - trailer_bytes)
                trailer_bytes += len(trailer)
                if trailer == b"\r\n":
                    return bytes(result)
                if trailer[:1] in {b" ", b"\t"} or b":" not in trailer:
                    raise NetworkFetchError("protocol_error")
        result.extend(reader.read_exact(size))
        if reader.read_exact(2) != b"\r\n":
            raise NetworkFetchError("protocol_error")


def _read_manifest_body(reader: _BufferedSocket, headers: Mapping[str, str]) -> bytes:
    content_length = headers.get("content-length")
    transfer_encoding = headers.get("transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        raise NetworkFetchError("protocol_error")
    if transfer_encoding is not None:
        if transfer_encoding.strip().lower() != "chunked":
            raise NetworkFetchError("protocol_error")
        return _read_chunked_body(reader, MANIFEST_BODY_LIMIT_BYTES)
    if content_length is not None:
        if not content_length.isdigit():
            raise NetworkFetchError("protocol_error")
        size = int(content_length, 10)
        if size > MANIFEST_BODY_LIMIT_BYTES:
            raise NetworkFetchError("response_too_large")
        return reader.read_exact(size)
    return reader.read_to_eof(MANIFEST_BODY_LIMIT_BYTES)


class ControlledHTTPSConnector:
    """Raw-socket connector with dependency injection for deterministic tests."""

    def __init__(
        self,
        *,
        resolver: Callable[[str, int], Sequence[str]] = _system_resolver,
        socket_factory: Callable[..., socket.socket] = socket.socket,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver
        self._socket_factory = socket_factory
        self._ssl_context_factory = ssl_context_factory
        self._monotonic = monotonic

    def fetch(
        self,
        raw_url: str,
        *,
        scope: FetchScope,
        timeouts: Optional[FetchTimeouts] = None,
    ) -> FetchResponse:
        if not isinstance(scope, FetchScope):
            raise NetworkFetchError("policy_rejected")
        parsed = _canonical_https_url(
            raw_url,
            maximum_utf8_bytes=(
                16384 if scope is FetchScope.MANIFEST_RELEASE else 2048
            ),
        )
        selected_timeouts = timeouts or (
            MANIFEST_TIMEOUTS if scope is FetchScope.MANIFEST_RELEASE else TARGET_TIMEOUTS
        )
        start = self._monotonic()
        total_deadline = start + selected_timeouts.total_seconds
        addresses = _resolve_public_addresses(
            parsed.hostname,
            resolver=self._resolver,
            timeout=min(
                selected_timeouts.connect_seconds,
                _remaining(total_deadline, self._monotonic),
            ),
        )
        pinned = addresses[0]
        family, endpoint = _sockaddr(pinned)
        raw_socket: Optional[socket.socket] = None
        tls_socket: Optional[ssl.SSLSocket] = None
        try:
            raw_socket = self._socket_factory(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            _set_timeout(
                raw_socket,
                selected_timeouts.connect_seconds,
                total_deadline,
                self._monotonic,
            )
            try:
                raw_socket.connect(endpoint)
            except socket.timeout:
                raise NetworkFetchError("timeout") from None
            except OSError:
                raise NetworkFetchError("connection_error") from None
            if not _same_peer(pinned, raw_socket.getpeername()):
                raise NetworkFetchError("policy_rejected")
            context = self._ssl_context_factory()
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise NetworkFetchError("tls_error")
            _set_timeout(
                raw_socket,
                selected_timeouts.connect_seconds,
                total_deadline,
                self._monotonic,
            )
            try:
                tls_socket = context.wrap_socket(
                    raw_socket,
                    server_hostname=parsed.hostname,
                )
                raw_socket = None
            except (ssl.CertificateError, ssl.SSLError):
                raise NetworkFetchError("tls_error") from None
            except socket.timeout:
                raise NetworkFetchError("timeout") from None
            except OSError:
                raise NetworkFetchError("connection_error") from None
            if not _same_peer(pinned, tls_socket.getpeername()):
                raise NetworkFetchError("policy_rejected")
            user_agent = (
                MANIFEST_USER_AGENT
                if scope is FetchScope.MANIFEST_RELEASE
                else TARGET_USER_AGENT
            )
            request = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ) % (parsed.transport_request_target(), parsed.hostname, user_agent)
            encoded = request.encode("ascii")
            _set_timeout(tls_socket, selected_timeouts.total_seconds, total_deadline, self._monotonic)
            try:
                tls_socket.sendall(encoded)
            except socket.timeout:
                raise NetworkFetchError("timeout") from None
            except (ssl.SSLError, OSError):
                raise NetworkFetchError("connection_error") from None
            reader = _BufferedSocket(
                tls_socket,
                deadline=total_deadline,
                head_deadline=self._monotonic() + selected_timeouts.response_head_seconds,
                monotonic=self._monotonic,
            )
            head = reader.read_head(HEADER_LIMIT_BYTES)
            status, headers = _parse_response_head(head)
            # Policy and response-boundary checks precede any status/retry
            # interpretation (including the 503 + gzip oracle).
            _validate_encoding(headers)
            if status < 200 or status == 101:
                raise NetworkFetchError("protocol_error")
            body = b""
            if scope is FetchScope.MANIFEST_RELEASE and status == 200:
                body = _read_manifest_body(reader, headers)
            # Target bodies and every non-200 Manifest body are read zero bytes.
            return FetchResponse(status, dict(headers), body, pinned)
        except NetworkFetchError:
            raise
        except socket.timeout:
            raise NetworkFetchError("timeout") from None
        except ssl.SSLError:
            raise NetworkFetchError("tls_error") from None
        except OSError:
            raise NetworkFetchError("connection_error") from None
        except Exception:
            raise NetworkFetchError("protocol_error") from None
        finally:
            if tls_socket is not None:
                try:
                    tls_socket.close()
                except Exception:
                    pass
            if raw_socket is not None:
                try:
                    raw_socket.close()
                except Exception:
                    pass

    def fetch_manifest(self, raw_url: str) -> FetchResponse:
        return self.fetch(raw_url, scope=FetchScope.MANIFEST_RELEASE)

    def fetch_target(self, raw_url: str) -> FetchResponse:
        return self.fetch(raw_url, scope=FetchScope.TARGET)


def fetch_manifest_once(
    raw_url: str, *, connector: Optional[ControlledHTTPSConnector] = None
) -> FetchResponse:
    return (connector or ControlledHTTPSConnector()).fetch_manifest(raw_url)


def fetch_target_once(
    raw_url: str, *, connector: Optional[ControlledHTTPSConnector] = None
) -> FetchResponse:
    return (connector or ControlledHTTPSConnector()).fetch_target(raw_url)


__all__ = [
    "CanonicalHTTPSURL",
    "ControlledHTTPSConnector",
    "FetchResponse",
    "FetchScope",
    "FetchTimeouts",
    "HEADER_LIMIT_BYTES",
    "IANA_IPV6_SNAPSHOT_PROVENANCE",
    "MANIFEST_BODY_LIMIT_BYTES",
    "MANIFEST_TIMEOUTS",
    "NetworkFetchError",
    "TARGET_TIMEOUTS",
    "TARGET_USER_AGENT",
    "fetch_manifest_once",
    "fetch_target_once",
]
