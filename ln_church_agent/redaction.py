"""Shared outbound-boundary redaction helpers.

These helpers intentionally do not alter request/canonical URLs.  They are
used only when a URL or metadata copy crosses into Evidence persistence or a
remote advisory service.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, unquote_to_bytes, urlencode, urlsplit, urlunsplit

from .navigation import FORBIDDEN_REDIRECT_PORTS


QUERY_REDACTION = "REDACTED"
_ABSOLUTE_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_INSPECT_PRIVATE_HOST_SUFFIXES = (
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
    ".nip.io",
    ".sslip.io",
    ".xip.io",
)
_INSPECT_METADATA_HOSTS = frozenset(
    {
        "internal",
        "local",
        "localdomain",
        "home.arpa",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_INSPECT_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "192.0.0.192",
        "168.63.129.16",
        "fd00:ec2::254",
    }
)
_INSPECT_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_INSPECT_ZERO_V4 = ipaddress.ip_network("0.0.0.0/8")
_INSPECT_IPV6_TRANSITION_NETWORKS = (
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_INSPECT_HOST_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_HEX = frozenset("0123456789abcdefABCDEF")
_INSPECT_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"(?i)(?:^|[^0-9a-f])(?:0x)?[0-9a-f]{64}(?:$|[^0-9a-f])"),
    re.compile(r"^[1-9A-HJ-NP-Za-km-z]{45,128}$"),
    re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)(?:lnbc|lntb|lnbcrt)[0-9][a-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
)
_INSPECT_SECRET_PATH_SEGMENTS = frozenset({
    "authorization", "proxy_authorization", "cookie", "set_cookie",
    "macaroon", "preimage", "private_key", "signature",
    "signature_input", "payment_signature", "receipt_token",
    "access_token", "refresh_token", "grant_token", "mandate_token",
    "shared_payment_token", "credential", "credentials", "secret",
    "api_key", "bearer", "proof", "invoice",
})


def _inspect_address_is_forbidden(raw_address: Any) -> bool:
    """Return the shared, version-independent Inspect address decision."""
    try:
        address = ipaddress.ip_address(raw_address)
    except (TypeError, ValueError):
        return True

    canonical = address.compressed.lower()
    if canonical in _INSPECT_METADATA_ADDRESSES:
        return True
    if isinstance(address, ipaddress.IPv4Address) and (
        address in _INSPECT_CGNAT or address in _INSPECT_ZERO_V4
    ):
        return True
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
        or any(
            address in network
            for network in _INSPECT_IPV6_TRANSITION_NETWORKS
        )
    ):
        return True
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, "is_site_local", False)
        or not address.is_global
    )


def _inspect_hostname_is_forbidden(raw_host: Any) -> bool:
    """Return the shared pre-resolution Inspect hostname decision."""
    if not isinstance(raw_host, str) or not raw_host:
        return True
    host = raw_host[:-1] if raw_host.endswith(".") else raw_host
    host = host.lower()
    if (
        not host
        or "%" in host
        or host in _INSPECT_METADATA_HOSTS
        or host == "localhost"
        or host.endswith(_INSPECT_PRIVATE_HOST_SUFFIXES)
    ):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." not in host
    return _inspect_address_is_forbidden(host)


def _contains_inspect_encoded_control(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX
            or value[index + 2] not in _HEX
        ):
            return True
        decoded = int(value[index + 1:index + 3], 16)
        if decoded < 0x20 or decoded in {0x5C, 0x7F}:
            return True
        index += 3
    try:
        decoded_text = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return True
    return any(0x7F <= ord(char) <= 0x9F for char in decoded_text)


def _contains_inspect_secret_material(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidates = [value]
    try:
        candidates.append(
            unquote_to_bytes(value).decode("utf-8", errors="ignore")
        )
    except Exception:
        pass
    candidates.extend(
        segment
        for candidate in tuple(candidates)
        for segment in candidate.split("/")
        if segment
    )
    return any(
        pattern.search(candidate) is not None
        for candidate in candidates
        for pattern in _INSPECT_SECRET_VALUE_PATTERNS
    )


def _contains_inspect_path_secret_material(path: Any) -> bool:
    if not isinstance(path, str):
        return False
    if _contains_inspect_secret_material(path):
        return True
    try:
        decoded = unquote_to_bytes(path).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return True
    if re.search(r"(?i)(?:^|[/;=])(?:bearer|basic)(?:[ /;=]|$)", decoded):
        return True
    normalized_segments = {
        re.sub(r"[^a-z0-9]+", "_", segment.lower()).strip("_")
        for segment in re.split(r"[/;=]", decoded)
        if segment
    }
    if normalized_segments.intersection(_INSPECT_SECRET_PATH_SEGMENTS):
        return True
    semantic_labels = {
        label.replace("_", "-")
        for label in _INSPECT_SECRET_PATH_SEGMENTS
    }
    for segment in re.split(r"[/;=]", decoded):
        normalized = _normalize_name(segment)
        if any(
            normalized == label
            or normalized.startswith(label + "-")
            or normalized.endswith("-" + label)
            or ("-" + label + "-") in normalized
            for label in semantic_labels
        ):
            return True
    return False


def _normalize_name(value: Any) -> str:
    raw = str(value).strip()
    raw = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", raw)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", raw)
    return re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")


def is_secret_query_key(key: Any) -> bool:
    """Classify credential-like metadata fields (not URL query policy)."""
    normalized = _normalize_name(key)
    compact = normalized.replace("-", "")
    parts = set(normalized.split("-")) if normalized else set()
    exact = {
        "sig", "auth", "jwt", "code", "state", "key", "authorization",
        "proxy-authorization", "api-key", "x-api-key", "private-key",
        "client-secret", "access-token", "refresh-token", "probe-token",
        "idempotency-key", "cookie", "set-cookie", "macaroon", "preimage",
        "password", "secret", "credential", "credentials", "bearer",
        "proof", "signature", "signature-input", "dpop", "reset-code",
        "oob-code", "saml-response", "ticket",
    }
    if normalized in exact:
        return True
    credential_parts = {
        "signature", "credential", "credentials", "token", "secret",
        "password", "preimage", "macaroon", "authorization", "proof",
        "cookie", "bearer", "code", "ticket", "jwt", "auth", "sig",
    }
    if parts.intersection(credential_parts):
        return True
    if {"api", "key"}.issubset(parts) or {"private", "key"}.issubset(parts):
        return True
    return compact.endswith(tuple(part for part in credential_parts))


def _contains_inspect_query_key_secret_material(key: Any) -> bool:
    """Detect secret material embedded in a URL query key.

    Ordinary semantic and standard signing parameter names may remain visible
    for compatibility.  A key that contains an actual credential pattern, or
    appends data to a sensitive semantic label, is not safe to expose.
    """
    if _contains_inspect_secret_material(key):
        return True
    normalized = _normalize_name(key)
    semantic_labels = {
        label.replace("_", "-")
        for label in _INSPECT_SECRET_PATH_SEGMENTS
    }
    safe_standard_names = semantic_labels.union({
        "x-amz-credential",
        "x-amz-signature",
        "x-goog-signature",
        "x-goog-credential",
    })
    return (
        normalized not in safe_standard_names
        and _contains_inspect_path_secret_material(key)
    )


def redact_url_query(
    url: Any,
) -> Any:
    """Preserve non-secret query keys while replacing every public value.

    Query values can contain PII or one-time credentials under arbitrary keys,
    so an outbound advisory/persistence boundary cannot safely use a denylist.
    Credential-shaped keys are replaced too because attackers can concatenate
    the secret material into the key itself.
    """
    if not isinstance(url, str) or "?" not in url:
        return url
    try:
        parsed = urlsplit(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_items = [
            (
                QUERY_REDACTION
                if _contains_inspect_query_key_secret_material(key)
                else key,
                QUERY_REDACTION,
            )
            for key, _value in query_items
        ]
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(redacted_items),
                parsed.fragment,
            )
        )
    except Exception:
        base, _separator, _query = url.partition("?")
        return base + "?" + QUERY_REDACTION


def redact_inspect_public_url(url: Any) -> str:
    """Return the only URL form that Inspect may expose publicly.

    The representation is built positively from a public scheme, canonical
    authority, and a fixed root path.  No caller-controlled path, query, or
    fragment crosses the CLI, MCP, observation, validator, or wire boundary.
    Forbidden/internal authorities collapse the entire URL to a fixed marker.
    """
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 8192
        or url != url.strip()
        or "\\" in url
        or _contains_inspect_encoded_control(url)
        or any(
            ord(char) <= 0x20 or 0x7F <= ord(char) <= 0x9F
            for char in url
        )
    ):
        return QUERY_REDACTION
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.netloc
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
            or parsed.netloc.endswith(":")
        ):
            return QUERY_REDACTION

        scheme = parsed.scheme.lower()
        explicit_port = parsed.port  # rejects malformed/out-of-range ports
        raw_host = parsed.hostname
        try:
            address = ipaddress.ip_address(raw_host)
        except ValueError:
            candidate = raw_host[:-1] if raw_host.endswith(".") else raw_host
            try:
                host = candidate.encode("idna").decode("ascii").lower()
            except (UnicodeError, UnicodeDecodeError):
                return QUERY_REDACTION
            if (
                not host
                or len(host) > 253
                or any(
                    _INSPECT_HOST_LABEL_RE.fullmatch(label) is None
                    for label in host.split(".")
                )
                or all(
                    label.isdigit()
                    or re.fullmatch(r"0x[0-9a-f]+", label) is not None
                    for label in host.split(".")
                )
                or _inspect_hostname_is_forbidden(host)
            ):
                return QUERY_REDACTION
        else:
            if _inspect_address_is_forbidden(address):
                return QUERY_REDACTION
            host = address.compressed.lower()

        port = explicit_port if explicit_port is not None else (
            443 if scheme == "https" else 80
        )
        if port == 0 or port in FORBIDDEN_REDIRECT_PORTS:
            return QUERY_REDACTION
        display_host = "[%s]" % host if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        authority = (
            display_host
            if port == default_port
            else "%s:%d" % (display_host, port)
        )
        return urlunsplit((scheme, authority, "/", "", ""))
    except Exception:
        return QUERY_REDACTION


def redact_urls_in_text(value: Any) -> Any:
    """Redact query values in every absolute HTTP(S) URL inside a string."""
    if not isinstance(value, str) or "http" not in value.lower() or "?" not in value:
        return value

    def replace(match: re.Match) -> str:
        candidate = match.group(0)
        trailing = ""
        while candidate and candidate[-1] in ".,);]}":
            # ``sanitize_error_msg`` uses ``[REDACTED]`` for inline
            # credentials.  Keep that marker inside a matched URL so the URL
            # pass can normalize the whole query value to ``REDACTED``.
            if candidate.endswith("[REDACTED]"):
                break
            trailing = candidate[-1] + trailing
            candidate = candidate[:-1]
        return str(redact_url_query(candidate)) + trailing

    return _ABSOLUTE_HTTP_URL_RE.sub(replace, value)


def redact_remote_metadata(value: Any, *, field_name: Any = None) -> Any:
    """Return a non-mutating advisory copy with secret fields redacted."""
    if field_name is not None and is_secret_query_key(field_name):
        return QUERY_REDACTION
    if isinstance(value, dict):
        return {
            key: redact_remote_metadata(item, field_name=key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_remote_metadata(item) for item in value]
    if isinstance(value, tuple):
        return [redact_remote_metadata(item) for item in value]
    if isinstance(value, str):
        return redact_urls_in_text(value)
    return value
