"""Strict URL and redirect-target validation for payment-bearing requests.

The transport still owns the actual connection.  This module makes the policy
decision explicit and testable before any redirected request is attempted.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from typing import Callable, Iterable, Tuple
from urllib.parse import urlsplit, urlunsplit

from .exceptions import NavigationGuardrailError


# Ports that commonly expose non-HTTP administrative, database, or local
# service protocols.  HTTP(S) on arbitrary application ports remains possible,
# but a redirect cannot be used as a cross-protocol primitive for these ports.
FORBIDDEN_REDIRECT_PORTS = frozenset(
    {
        1, 7, 9, 11, 13, 15, 17, 19,
        20, 21, 22, 23, 25,
        37, 42, 43, 53, 69, 77, 79, 87, 95,
        101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123,
        135, 137, 138, 139, 143, 161, 162, 179,
        389, 427, 445, 465,
        512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556,
        563, 587, 601, 636,
        993, 995, 2049, 2375, 3260, 3389, 4045, 4190, 5353, 5432,
        5900, 5984, 6379, 6667, 8086, 9200, 11211, 27017,
    }
)


@dataclass(frozen=True)
class CanonicalHttpTarget:
    scheme: str
    host: str
    port: int
    origin: str
    url: str
    # Populated only by ``validate_redirect_target``.  A caller can use one of
    # these already-vetted addresses as the actual transport destination while
    # retaining ``host`` for HTTP Host and TLS SNI/certificate verification.
    # This closes the validation-to-connect DNS rebinding window.
    addresses: Tuple[str, ...] = ()


AddressResolver = Callable[[str, int], Iterable[str]]


def resolve_host_addresses(host: str, port: int) -> Tuple[str, ...]:
    """Resolve every address returned by the system resolver.

    Returning all answers is intentional: accepting one public answer while a
    private answer is also present would leave a DNS-rebinding/selection gap.
    """

    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target DNS resolution failed."
        ) from exc
    addresses = tuple(sorted({str(record[4][0]) for record in records}))
    if not addresses:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target DNS returned no addresses."
        )
    return addresses


def _require_public_address(raw: str) -> None:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target resolved to an invalid address."
        ) from exc
    if not address.is_global:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target resolved to a non-public address."
        )


def canonicalize_http_target(url: str) -> CanonicalHttpTarget:
    if not isinstance(url, str) or not url or url != url.strip():
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target must be a canonical absolute URL."
        )
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target has an invalid port."
        ) from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target must use HTTP or HTTPS."
        )
    if parsed.username is not None or parsed.password is not None:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target userinfo is forbidden."
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target host is missing."
        )
    port = port or (443 if scheme == "https" else 80)
    if port in FORBIDDEN_REDIRECT_PORTS:
        raise NavigationGuardrailError(
            "Fail-Closed: Redirect target port is forbidden."
        )

    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port == default_port else f"{display_host}:{port}"
    origin = f"{scheme}://{authority}"
    path = parsed.path or "/"
    canonical_url = urlunsplit((scheme, authority, path, parsed.query, ""))
    return CanonicalHttpTarget(scheme, host, port, origin, canonical_url)


def validate_redirect_target(
    url: str,
    *,
    resolver: AddressResolver = resolve_host_addresses,
) -> CanonicalHttpTarget:
    """Canonicalize a target and reject every non-public resolved address."""

    target = canonicalize_http_target(url)
    try:
        literal = ipaddress.ip_address(target.host)
    except ValueError:
        addresses = tuple(sorted({str(value) for value in resolver(target.host, target.port)}))
        if not addresses:
            raise NavigationGuardrailError(
                "Fail-Closed: Redirect target DNS returned no addresses."
            )
        for address in addresses:
            _require_public_address(address)
    else:
        addresses = (str(literal),)
        _require_public_address(addresses[0])
    return CanonicalHttpTarget(
        target.scheme,
        target.host,
        target.port,
        target.origin,
        target.url,
        addresses,
    )
