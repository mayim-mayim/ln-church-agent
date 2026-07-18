"""Strict, side-effect-free interpretation of HTTP payment receipts.

Receipt presence, server assertion, signature verification, settlement
verification, and HTTP delivery are deliberately independent signals.  In
particular, decoding JSON is never treated as cryptographic verification.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple


SignatureVerifier = Callable[[str], Optional[Dict[str, Any]]]
SettlementBindingChecker = Callable[[Mapping[str, Any]], bool]

_RECEIPT_HEADER_NAMES = frozenset(("payment-response", "payment-receipt"))
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_JWS_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_RECEIPT_TOKEN_CHARS = 64 * 1024
_RECEIPT_PARAM_RE = re.compile(
    r'(?:^|,)\s*receipt\s*=\s*(?:"([^"\\]*)"|([^,\s]+))\s*(?=,|$)',
    re.IGNORECASE,
)


class _MalformedJSON(ValueError):
    pass


@dataclass(frozen=True)
class ReceiptState:
    """Five independent receipt/delivery signals plus safe diagnostics.

    ``token`` and ``claims`` are excluded from ``repr`` so accidentally logging
    this object does not disclose a bearer-like receipt or its contents.
    ``error`` is always a stable code and never contains either value.
    """

    present: bool
    server_asserted: bool
    signature_verified: bool
    settlement_verified: bool
    delivered: bool
    format: Optional[str] = None
    error: Optional[str] = None
    token: Optional[str] = field(default=None, repr=False, compare=False)
    claims: Optional[Mapping[str, Any]] = field(
        default=None, repr=False, compare=False
    )


def _reject_constant(value: str) -> None:
    del value
    raise _MalformedJSON("non-finite JSON number")


def _object_without_duplicate_keys(pairs: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _MalformedJSON("duplicate JSON key")
        result[key] = value
    return result


def _strict_json_object(raw: bytes) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _MalformedJSON):
        return None
    return value if isinstance(value, dict) else None


def _decode_base64_segment(value: str, *, urlsafe: bool) -> Optional[bytes]:
    pattern = _BASE64URL_RE if urlsafe else _BASE64_RE
    if not value or pattern.fullmatch(value) is None:
        return None
    unpadded = value.rstrip("=")
    supplied_padding = len(value) - len(unpadded)
    required_padding = (-len(unpadded)) % 4
    if supplied_padding not in (0, required_padding):
        return None
    padded = unpadded + ("=" * required_padding)
    try:
        return base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_" if urlsafe else None,
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        return None


def _payment_response_value(value: str) -> str:
    """Return the receipt parameter from the deployed structured header shape."""
    if "=" not in value:
        return value
    matches = list(_RECEIPT_PARAM_RE.finditer(value))
    if len(matches) != 1:
        return ""
    return (matches[0].group(1) or matches[0].group(2) or "").strip()


def _header_values(headers: Mapping[str, Any]) -> Tuple[bool, Tuple[str, ...]]:
    present = False
    values = []
    try:
        items = headers.items()
    except AttributeError:
        return False, ()

    for raw_name, raw_value in items:
        if not isinstance(raw_name, str):
            continue
        normalized_name = raw_name.strip().lower()
        if normalized_name not in _RECEIPT_HEADER_NAMES:
            continue
        present = True
        candidates = raw_value if isinstance(raw_value, (list, tuple)) else (raw_value,)
        for candidate in candidates:
            if isinstance(candidate, bytes):
                try:
                    candidate = candidate.decode("ascii")
                except UnicodeDecodeError:
                    values.append("")
                    continue
            if not isinstance(candidate, str):
                values.append("")
                continue
            candidate = candidate.strip()
            if normalized_name == "payment-response":
                candidate = _payment_response_value(candidate)
            values.append(candidate)
    return present, tuple(values)


def _extract_token(headers: Mapping[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
    present, values = _header_values(headers)
    if not present:
        return False, None, None
    if not values or any(not value for value in values):
        return True, None, "malformed_receipt"
    if any(len(value) > _MAX_RECEIPT_TOKEN_CHARS for value in values):
        return True, None, "malformed_receipt"
    first = values[0]
    if any(value != first for value in values[1:]):
        return True, None, "conflicting_receipt_headers"
    return True, first, None


def _decode_unsigned_json(token: str) -> Optional[Dict[str, Any]]:
    alphabets = []
    if _BASE64URL_RE.fullmatch(token) is not None:
        alphabets.append(True)
    if _BASE64_RE.fullmatch(token) is not None:
        alphabets.append(False)
    for urlsafe in alphabets:
        decoded = _decode_base64_segment(token, urlsafe=urlsafe)
        if decoded is not None:
            value = _strict_json_object(decoded)
            if value is not None:
                return value
    return None


def _decode_compact_jws(token: str) -> Optional[Dict[str, Any]]:
    segments = token.split(".")
    if len(segments) != 3 or any(_JWS_SEGMENT_RE.fullmatch(part) is None for part in segments):
        return None
    protected = _decode_base64_segment(segments[0], urlsafe=True)
    payload = _decode_base64_segment(segments[1], urlsafe=True)
    signature = _decode_base64_segment(segments[2], urlsafe=True)
    if protected is None or payload is None or not signature:
        return None
    if _strict_json_object(protected) is None:
        return None
    return _strict_json_object(payload)


def evaluate_payment_receipt(
    headers: Mapping[str, Any],
    status_code: int,
    *,
    signature_verifier: Optional[SignatureVerifier] = None,
    settlement_binding_checker: Optional[SettlementBindingChecker] = None,
) -> ReceiptState:
    """Extract and evaluate a payment receipt without performing any I/O.

    A signature verifier must return the verified claims dictionary, or
    ``None`` on any failure (including a wrong key or an expired token).
    Settlement is true only when a signature has been verified and the
    separate binding checker accepts those verified claims.
    """

    delivered = isinstance(status_code, int) and not isinstance(status_code, bool)
    delivered = delivered and 200 <= status_code < 300
    present, token, extraction_error = _extract_token(headers)
    if token is None:
        return ReceiptState(
            present=present,
            server_asserted=False,
            signature_verified=False,
            settlement_verified=False,
            delivered=delivered,
            error=extraction_error,
        )

    if token.count(".") == 2:
        decoded_claims = _decode_compact_jws(token)
        if decoded_claims is None:
            return ReceiptState(
                present=True,
                server_asserted=False,
                signature_verified=False,
                settlement_verified=False,
                delivered=delivered,
                error="malformed_receipt",
            )

        verified_claims: Optional[Dict[str, Any]] = None
        verification_error = None
        if signature_verifier is not None:
            try:
                candidate = signature_verifier(token)
            except Exception:  # Verifiers are a fail-closed trust boundary.
                candidate = None
            if isinstance(candidate, dict) and candidate == decoded_claims:
                verified_claims = candidate
            else:
                verification_error = "signature_verification_failed"

        signature_verified = verified_claims is not None
        settlement_verified = False
        if signature_verified and settlement_binding_checker is not None:
            try:
                settlement_verified = settlement_binding_checker(verified_claims) is True
            except Exception:  # Binding failures must not escape as trust.
                settlement_verified = False
            if not settlement_verified:
                verification_error = "settlement_verification_failed"

        return ReceiptState(
            present=True,
            server_asserted=True,
            signature_verified=signature_verified,
            settlement_verified=settlement_verified,
            delivered=delivered,
            format="jws",
            error=verification_error,
            token=token,
            claims=verified_claims if signature_verified else decoded_claims,
        )

    claims = _decode_unsigned_json(token)
    if claims is None:
        return ReceiptState(
            present=True,
            server_asserted=False,
            signature_verified=False,
            settlement_verified=False,
            delivered=delivered,
            error="malformed_receipt",
        )
    return ReceiptState(
        present=True,
        server_asserted=True,
        signature_verified=False,
        settlement_verified=False,
        delivered=delivered,
        format="unsigned_base64json",
        token=token,
        claims=claims,
    )


__all__ = [
    "ReceiptState",
    "SettlementBindingChecker",
    "SignatureVerifier",
    "evaluate_payment_receipt",
]
