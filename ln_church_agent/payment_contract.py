"""Pure helpers for the P0-2 canonical payment contract.

The wire contract is intentionally small and strict so that Python agents and
JavaScript providers hash exactly the same payment requirement.  This module
does not perform network I/O, wallet calls, or payment execution.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit


CANONICAL_PAYMENT_REQUIREMENT_SCHEMA_VERSION = (
    "ln_church.canonical_payment_requirement.v1"
)

# Twenty hash-bound fields plus the requirement_hash that authenticates them.
CANONICAL_REQUIREMENT_HASH_FIELDS = (
    "schema_version",
    "url_scheme",
    "host",
    "port",
    "origin",
    "method",
    "resource_url",
    "rail",
    "authorization_scheme",
    "asset_identifier",
    "chain",
    "network",
    "decimals",
    "amount_atomic",
    "pay_to",
    "expires_at",
    "challenge_id",
    "payment_id",
    "idempotency_key",
    "credential_payload_hash",
)
CANONICAL_REQUIREMENT_FIELDS = (
    *CANONICAL_REQUIREMENT_HASH_FIELDS,
    "requirement_hash",
)

_HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
_HTTP_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*$")
_PAYMENT_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_COMPRESSED_PUBKEY_RE = re.compile(r"^(?:02|03)[a-f0-9]{64}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class PaymentContractError(ValueError):
    """Raised when a payment requirement cannot be safely canonicalized."""


def _assert_canonical_json_value(value: Any, path: str) -> None:
    if value is None:
        raise PaymentContractError(f"{path} must not be null.")
    if isinstance(value, float):
        raise PaymentContractError(f"{path} must not contain floating-point values.")
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise PaymentContractError(
                f"{path} must be a cross-runtime safe integer."
            )
        return
    if isinstance(value, (list, tuple)):
        for index, entry in enumerate(value):
            _assert_canonical_json_value(entry, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, entry in value.items():
            if not isinstance(key, str):
                raise PaymentContractError(f"{path} contains a non-string key.")
            _assert_canonical_json_value(entry, f"{path}.{key}")
        return
    raise PaymentContractError(f"{path} contains an unsupported JSON value.")


def canonical_json(value: Any) -> str:
    """Return recursive key-sorted compact JSON compatible with JSON.stringify."""

    _assert_canonical_json_value(value, "canonical_json")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_prefixed(value: Any) -> str:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise PaymentContractError("SHA-256 input must be UTF-8 text or bytes.")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PaymentContractError(f"{field} must be a non-empty string.")
    return value


def _host_for_url(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _canonical_url_parts(url: str) -> Dict[str, Any]:
    if not isinstance(url, str) or not url:
        raise PaymentContractError("resource_url must be a non-empty URL string.")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PaymentContractError("resource_url contains an invalid port.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise PaymentContractError("Only HTTP(S) request targets are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise PaymentContractError("resource_url must not contain userinfo.")
    if parsed.fragment:
        raise PaymentContractError("resource_url must not contain a fragment.")

    host = (parsed.hostname or "").lower()
    if not host:
        raise PaymentContractError("resource_url must contain a host.")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    host_for_url = _host_for_url(host)
    default_port = 443 if scheme == "https" else 80
    authority = (
        host_for_url
        if effective_port == default_port
        else f"{host_for_url}:{effective_port}"
    )
    origin = f"{scheme}://{authority}"
    resource_url = urlunsplit(
        (scheme, authority, parsed.path or "/", parsed.query, "")
    )
    return {
        "url_scheme": scheme,
        "host": host,
        "port": effective_port,
        "origin": origin,
        "resource_url": resource_url,
    }


def canonical_request_target(url: str, method: str) -> Dict[str, Any]:
    target = _canonical_url_parts(url)
    if not isinstance(method, str) or _HTTP_METHOD_RE.fullmatch(method.upper()) is None:
        raise PaymentContractError("HTTP method is invalid.")
    target["method"] = method.upper()
    return target


def validate_canonical_requirement_shape(
    requirement: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(requirement, Mapping):
        raise PaymentContractError("Canonical requirement must be an object.")

    actual_keys = set(requirement.keys())
    expected_keys = set(CANONICAL_REQUIREMENT_FIELDS)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise PaymentContractError(
            "Canonical requirement keys must exactly match the frozen schema "
            f"(missing={missing}, extra={extra})."
        )

    value = dict(requirement)
    _assert_canonical_json_value(value, "canonical_requirement")
    if value["schema_version"] != CANONICAL_PAYMENT_REQUIREMENT_SCHEMA_VERSION:
        raise PaymentContractError(
            "Unsupported canonical payment requirement schema_version."
        )

    string_fields = set(CANONICAL_REQUIREMENT_FIELDS) - {"port", "decimals"}
    for field in sorted(string_fields):
        _require_non_empty_string(value[field], field)

    if value["url_scheme"] not in {"http", "https"}:
        raise PaymentContractError("url_scheme must be http or https.")
    if value["host"] != value["host"].lower():
        raise PaymentContractError("host must be lowercase canonical form.")
    if (
        isinstance(value["port"], bool)
        or not isinstance(value["port"], int)
        or not 1 <= value["port"] <= 65535
    ):
        raise PaymentContractError("port must be an integer from 1 through 65535.")
    if _HTTP_METHOD_RE.fullmatch(value["method"]) is None:
        raise PaymentContractError("method must be uppercase canonical form.")
    if (
        isinstance(value["decimals"], bool)
        or not isinstance(value["decimals"], int)
        or not 0 <= value["decimals"] <= 30
    ):
        raise PaymentContractError("decimals must be an integer from 0 through 30.")
    if _POSITIVE_INTEGER_RE.fullmatch(value["amount_atomic"]) is None:
        raise PaymentContractError(
            "amount_atomic must be a positive canonical decimal string."
        )
    if _POSITIVE_INTEGER_RE.fullmatch(value["expires_at"]) is None:
        raise PaymentContractError(
            "expires_at must be a positive canonical Unix timestamp string."
        )
    for field in ("credential_payload_hash", "requirement_hash"):
        if _HASH_RE.fullmatch(value[field]) is None:
            raise PaymentContractError(
                f"{field} must use sha256:<lowercase hex> form."
            )

    resource = _canonical_url_parts(value["resource_url"])
    for field in ("url_scheme", "host", "port", "origin", "resource_url"):
        if value[field] != resource[field]:
            raise PaymentContractError(
                f"resource_url {field} does not match canonical requirement."
            )
    return value


def compute_requirement_hash(requirement: Mapping[str, Any]) -> str:
    value = validate_canonical_requirement_shape(requirement)
    hashable = {field: value[field] for field in CANONICAL_REQUIREMENT_HASH_FIELDS}
    return sha256_prefixed(canonical_json(hashable))


def build_canonical_payment_requirement(
    requirement_fields: Mapping[str, Any],
) -> Dict[str, Any]:
    """Build and validate a requirement from the twenty hash-bound fields."""
    if not isinstance(requirement_fields, Mapping):
        raise PaymentContractError("Canonical requirement input must be an object.")
    actual = set(requirement_fields)
    expected = set(CANONICAL_REQUIREMENT_HASH_FIELDS)
    if actual != expected:
        raise PaymentContractError(
            "Canonical requirement input keys must exactly match the frozen hash fields."
        )
    provisional = dict(requirement_fields)
    provisional["requirement_hash"] = "sha256:" + ("0" * 64)
    validate_canonical_requirement_shape(provisional)
    hashable = {
        field: provisional[field] for field in CANONICAL_REQUIREMENT_HASH_FIELDS
    }
    provisional["requirement_hash"] = sha256_prefixed(canonical_json(hashable))
    return verify_canonical_payment_requirement(provisional)


def verify_canonical_payment_requirement(
    requirement: Mapping[str, Any],
) -> Dict[str, Any]:
    value = validate_canonical_requirement_shape(requirement)
    expected = compute_requirement_hash(value)
    if value["requirement_hash"] != expected:
        raise PaymentContractError("Canonical payment requirement hash mismatch.")
    return value


def verify_request_binding(
    requirement: Mapping[str, Any], *, request_url: str, method: str
) -> Dict[str, Any]:
    value = verify_canonical_payment_requirement(requirement)
    target = canonical_request_target(request_url, method)
    for field in (
        "url_scheme",
        "host",
        "port",
        "origin",
        "method",
        "resource_url",
    ):
        if value[field] != target[field]:
            raise PaymentContractError(
                f"Canonical requirement is not bound to request field {field}."
            )
    return value


def verify_requirement_expiry(
    requirement: Mapping[str, Any], *, now: int
) -> Dict[str, Any]:
    value = verify_canonical_payment_requirement(requirement)
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise PaymentContractError("Verification clock must be a non-negative integer.")
    if now >= int(value["expires_at"]):
        raise PaymentContractError("Canonical payment requirement has expired.")
    return value


def verify_l402_metadata(
    requirement: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Bind decoded, signed BOLT11 metadata to one canonical requirement."""

    value = verify_canonical_payment_requirement(requirement)
    required_metadata = {
        "amount_atomic",
        "payment_hash",
        "payee",
        "network",
        "expires_at",
    }
    if not isinstance(metadata, Mapping) or set(metadata.keys()) != required_metadata:
        raise PaymentContractError(
            "L402 metadata must exactly contain amount_atomic, payment_hash, payee, "
            "network, and expires_at."
        )
    decoded = dict(metadata)
    _assert_canonical_json_value(decoded, "l402_metadata")
    for field in required_metadata:
        _require_non_empty_string(decoded[field], f"l402_metadata.{field}")

    if value["rail"] != "l402" or value["authorization_scheme"] != "L402":
        raise PaymentContractError("Canonical requirement is not an L402 requirement.")
    if (
        value["asset_identifier"] != "lightning:sats"
        or value["chain"] != "bitcoin"
        or value["decimals"] != 3
    ):
        raise PaymentContractError("Canonical L402 asset metadata is unsupported.")
    if decoded["network"] not in {
        "bitcoin-mainnet",
        "bitcoin-testnet",
        "bitcoin-regtest",
    }:
        raise PaymentContractError("Decoded BOLT11 network is unknown.")
    if _POSITIVE_INTEGER_RE.fullmatch(decoded["amount_atomic"]) is None:
        raise PaymentContractError("Decoded BOLT11 amount is not canonical.")
    if _POSITIVE_INTEGER_RE.fullmatch(decoded["expires_at"]) is None:
        raise PaymentContractError("Decoded BOLT11 expiry is not canonical.")
    if _PAYMENT_HASH_RE.fullmatch(decoded["payment_hash"]) is None:
        raise PaymentContractError("Decoded BOLT11 payment hash is invalid.")
    if _COMPRESSED_PUBKEY_RE.fullmatch(decoded["payee"]) is None:
        raise PaymentContractError("Decoded BOLT11 payee is invalid.")

    comparisons = {
        "amount_atomic": "amount_atomic",
        "payment_hash": "payment_id",
        "payee": "pay_to",
        "network": "network",
        "expires_at": "expires_at",
    }
    for decoded_field, requirement_field in comparisons.items():
        if decoded[decoded_field] != value[requirement_field]:
            raise PaymentContractError(
                f"Decoded BOLT11 {decoded_field} does not match canonical requirement."
            )
    if now is not None:
        verify_requirement_expiry(value, now=now)
    return value


def validate_l402_macaroon_structure(
    macaroon: str,
    *,
    canonical_requirement: Optional[Mapping[str, Any]] = None,
) -> None:
    """Validate the v1 packet stream consumed by the Server L402 verifier.

    An Agent cannot verify the provider's HMAC secret.  It can and must reject
    credentials that the advertised verifier will deterministically reject
    before an invoice is paid: malformed Base64, invalid/truncated packets,
    missing signature material, or canonical caveat divergence.
    """

    if (
        not isinstance(macaroon, str)
        or not macaroon
        or len(macaroon) > 32_768
        or macaroon != macaroon.strip()
        or re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", macaroon) is None
    ):
        raise PaymentContractError("L402 macaroon encoding is invalid.")
    try:
        decoded = base64.b64decode(
            macaroon + ("=" * (-len(macaroon) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        raise PaymentContractError("L402 macaroon Base64 is invalid.") from None
    if not decoded or len(decoded) > 32_768:
        raise PaymentContractError("L402 macaroon packet stream is invalid.")

    packets = []
    offset = 0
    while offset < len(decoded):
        if offset + 4 > len(decoded):
            raise PaymentContractError("L402 macaroon packet header is truncated.")
        header = decoded[offset : offset + 4]
        try:
            header_text = header.decode("ascii")
        except UnicodeDecodeError:
            raise PaymentContractError("L402 macaroon packet length is invalid.") from None
        if re.fullmatch(r"[0-9a-fA-F]{4}", header_text) is None:
            raise PaymentContractError("L402 macaroon packet length is invalid.")
        packet_size = int(header_text, 16)
        if packet_size < 7 or offset + packet_size > len(decoded):
            raise PaymentContractError("L402 macaroon packet is truncated.")
        packet = decoded[offset + 4 : offset + packet_size]
        if not packet.endswith(b"\n") or b" " not in packet[:-1]:
            raise PaymentContractError("L402 macaroon packet framing is invalid.")
        name, value = packet[:-1].split(b" ", 1)
        try:
            packet_name = name.decode("ascii")
        except UnicodeDecodeError:
            raise PaymentContractError("L402 macaroon packet name is invalid.") from None
        if packet_name not in {"location", "identifier", "cid", "signature"}:
            raise PaymentContractError("L402 macaroon contains an unsupported packet.")
        packets.append((packet_name, value))
        offset += packet_size
    if offset != len(decoded):
        raise PaymentContractError("L402 macaroon contains trailing bytes.")

    names = [name for name, _value in packets]
    if (
        names.count("location") != 1
        or names.count("identifier") != 1
        or names.count("signature") != 1
        or names[0:2] != ["location", "identifier"]
        or names[-1] != "signature"
        or any(name != "cid" for name in names[2:-1])
        or len(packets[-1][1]) != 32
    ):
        raise PaymentContractError("L402 macaroon packet sequence is invalid.")

    try:
        location = packets[0][1].decode("utf-8")
        identifier = packets[1][1].decode("utf-8")
        caveats = [value.decode("utf-8") for name, value in packets if name == "cid"]
    except UnicodeDecodeError:
        raise PaymentContractError("L402 macaroon text packet is not UTF-8.") from None
    if not location or not identifier:
        raise PaymentContractError("L402 macaroon location or identifier is empty.")

    caveat_map: Dict[str, str] = {}
    for caveat in caveats:
        if "=" not in caveat:
            raise PaymentContractError("L402 macaroon caveat is malformed.")
        name, value = caveat.split("=", 1)
        if not name or name in caveat_map:
            raise PaymentContractError("L402 macaroon caveat is duplicate or malformed.")
        caveat_map[name] = value

    if canonical_requirement is None:
        return
    canonical = verify_canonical_payment_requirement(canonical_requirement)
    expected_names = {
        "payment_hash",
        "amount",
        *(f"lnc.{field}" for field in CANONICAL_REQUIREMENT_FIELDS),
    }
    if set(caveat_map) != expected_names:
        raise PaymentContractError("L402 macaroon canonical caveat set is invalid.")
    if location != canonical["origin"] or identifier != canonical["challenge_id"]:
        raise PaymentContractError("L402 macaroon identity is not canonical-bound.")
    if caveat_map["payment_hash"] != canonical["payment_id"]:
        raise PaymentContractError("L402 macaroon payment hash is not canonical-bound.")
    atomic = int(canonical["amount_atomic"])
    scale = 10 ** int(canonical["decimals"])
    if atomic % scale or caveat_map["amount"] != str(atomic // scale):
        raise PaymentContractError("L402 macaroon amount is not canonical-bound.")
    for field in CANONICAL_REQUIREMENT_FIELDS:
        if caveat_map[f"lnc.{field}"] != str(canonical[field]):
            raise PaymentContractError(
                f"L402 macaroon lnc.{field} caveat is not canonical-bound."
            )
