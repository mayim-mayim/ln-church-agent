"""Shared outbound-boundary redaction helpers.

These helpers intentionally do not alter request/canonical URLs.  They are
used only when a URL or metadata copy crosses into Evidence persistence or a
remote advisory service.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


QUERY_REDACTION = "REDACTED"
_ABSOLUTE_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


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


def redact_url_query(
    url: Any,
) -> Any:
    """Preserve URL/query keys while replacing every persisted/remote value.

    Query values can contain PII or one-time credentials under arbitrary keys,
    so an outbound advisory/persistence boundary cannot safely use a denylist.
    """
    if not isinstance(url, str) or "?" not in url:
        return url
    try:
        parsed = urlsplit(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_items = [
            (key, QUERY_REDACTION)
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
