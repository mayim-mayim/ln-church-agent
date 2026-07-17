import base64
import json
import re
import time
import httpx
from typing import Any, Dict, Optional, Tuple
from decimal import Decimal, InvalidOperation

from .models import ParsedChallenge, ChallengeSource, SchemeType, CanonicalPaymentRequirement
from .exceptions import PaymentChallengeError
from .crypto.lightning import (
    decode_bolt11_amount_msats,
    decode_bolt11_payment_metadata,
)
from .payment_contract import (
    PaymentContractError,
    sha256_prefixed,
    verify_canonical_payment_requirement,
    validate_l402_macaroon_structure,
    verify_l402_metadata,
    verify_request_binding,
    verify_requirement_expiry,
)

ALLOWED_CURRENCIES = {"SATS", "USDC", "JPYC"}

_MISSING = object()
_AUTH_PARAM_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_CANONICAL_MPP_AMOUNT = re.compile(
    r"(?:[1-9][0-9]*|0\.[0-9]{0,2}[1-9]|[1-9][0-9]*\.[0-9]{0,2}[1-9])"
)


class _CasefoldCheckedJSONObject(dict):
    """Internal JSON object retaining duplicate-key detection metadata."""


def _parse_http_auth_params(raw_params: str) -> Tuple[Dict[str, str], bool]:
    """Parse auth-params without dropping empty values or case aliases."""
    params: Dict[str, str] = {}
    valid = True
    pos = 0
    length = len(raw_params)

    while pos < length:
        while pos < length and (raw_params[pos].isspace() or raw_params[pos] == ","):
            pos += 1
        if pos >= length:
            break

        name_match = _AUTH_PARAM_NAME.match(raw_params, pos)
        if name_match is None:
            return params, False
        name = name_match.group(0)
        pos = name_match.end()
        while pos < length and raw_params[pos].isspace():
            pos += 1
        if pos >= length or raw_params[pos] != "=":
            return params, False
        pos += 1
        while pos < length and raw_params[pos].isspace():
            pos += 1

        if pos < length and raw_params[pos] == '"':
            pos += 1
            value_chars = []
            closed = False
            while pos < length:
                char = raw_params[pos]
                if char == "\\":
                    pos += 1
                    if pos >= length:
                        return params, False
                    value_chars.append(raw_params[pos])
                    pos += 1
                elif char == '"':
                    pos += 1
                    closed = True
                    break
                else:
                    value_chars.append(char)
                    pos += 1
            if not closed:
                return params, False
            value = "".join(value_chars)
        else:
            value_start = pos
            while (
                pos < length
                and raw_params[pos] != ","
                and not raw_params[pos].isspace()
            ):
                pos += 1
            value = raw_params[value_start:pos]

        normalized_name = name.casefold()
        if normalized_name in params:
            valid = False
        else:
            params[normalized_name] = value

        while pos < length and raw_params[pos].isspace():
            pos += 1
        if pos < length and raw_params[pos] == ",":
            pos += 1

    return params, valid


def _decode_mpp_request(value: str) -> Tuple[Dict[str, Any], bool, bool]:
    """Decode request JSON and retain case-insensitive duplicate detection."""
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)

        def checked_object(pairs):
            obj = _CasefoldCheckedJSONObject()
            seen = set()
            duplicate = False
            for key, item in pairs:
                normalized_key = key.casefold()
                if normalized_key in seen:
                    duplicate = True
                else:
                    seen.add(normalized_key)
                    obj[key] = item
            obj._casefold_duplicate = duplicate
            return obj

        decoded = json.loads(
            decoded_bytes.decode("utf-8"), object_pairs_hook=checked_object
        )
        if not isinstance(decoded, dict):
            return {}, False, False

        def has_duplicate(item):
            if isinstance(item, dict):
                if getattr(item, "_casefold_duplicate", False):
                    return True
                return any(has_duplicate(child) for child in item.values())
            if isinstance(item, list):
                return any(has_duplicate(child) for child in item)
            return False

        def plain_json(item):
            if isinstance(item, dict):
                return {key: plain_json(child) for key, child in item.items()}
            if isinstance(item, list):
                return [plain_json(child) for child in item]
            return item

        duplicate = has_duplicate(decoded)
        return plain_json(decoded), True, duplicate
    except Exception:
        return {}, False, False


def _casefold_json_field(mapping: Dict[str, Any], field: str):
    matches = [
        value
        for key, value in mapping.items()
        if isinstance(key, str) and key.casefold() == field.casefold()
    ]
    if not matches:
        return False, _MISSING, True
    if len(matches) != 1:
        return True, matches[0], False
    return True, matches[0], True


def _same_semantic_value(left, right) -> bool:
    return type(left) is type(right) and left == right


def _resolve_mpp_field(
    params: Dict[str, Any],
    request_json: Dict[str, Any],
    method_details: Dict[str, Any],
    field: str,
):
    values = []
    if field in params:
        values.append(params[field])

    for mapping in (request_json, method_details):
        present, value, unique = _casefold_json_field(mapping, field)
        if not unique:
            return True, value, False
        if present:
            values.append(value)

    if not values:
        return False, _MISSING, True
    first = values[0]
    if any(not _same_semantic_value(first, value) for value in values[1:]):
        return True, first, False
    return True, first, True


def _resolve_mpp_control_field(
    params: Dict[str, Any],
    request_json: Dict[str, Any],
    method_details: Dict[str, Any],
    field: str,
):
    """Resolve method/intent without allowing one declaration to mask another."""
    values = []
    declarations_unique = True
    if field in params:
        values.append(params[field])

    for mapping in (request_json, method_details):
        present, value, unique = _casefold_json_field(mapping, field)
        if not unique:
            declarations_unique = False
        if present:
            values.append(value)

    if not values:
        return False, _MISSING, True, ()

    normalized_values = []
    values_valid = True
    for value in values:
        if not isinstance(value, str):
            values_valid = False
            continue
        normalized = value.strip().casefold()
        if not normalized:
            values_valid = False
            continue
        normalized_values.append(normalized)

    first = normalized_values[0] if normalized_values else _MISSING
    consistent = (
        declarations_unique
        and values_valid
        and bool(normalized_values)
        and all(value == first for value in normalized_values[1:])
    )
    return True, first, consistent, tuple(normalized_values)


def _normalize_mpp_currency(value) -> Optional[str]:
    if not isinstance(value, str) or value != value.strip():
        return None
    normalized = value.upper()
    if normalized not in {"SAT", "SATS"}:
        return None
    return "SATS"


def _canonical_mpp_amount_decimal(value) -> Optional[Decimal]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value) if value > 0 else None
    if not isinstance(value, str) or _CANONICAL_MPP_AMOUNT.fullmatch(value) is None:
        return None
    try:
        amount = Decimal(value)
    except InvalidOperation:
        return None
    if not amount.is_finite() or amount <= 0:
        return None
    return amount


def _canonical_positive_integer_string(value) -> Optional[str]:
    """Return the one accepted representation for an atomic payment amount."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return value
    return None

def b64url_decode_json(b64_str: str) -> dict:
    try:
        padded = b64_str + '=' * (-len(b64_str) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded = json.loads(decoded_bytes.decode('utf-8'))
        return decoded if isinstance(decoded, dict) else {}
    except Exception:
        return {}

def b64url_encode_json(data_dict: dict) -> str:
    json_str = json.dumps(data_dict)
    b64_bytes = base64.urlsafe_b64encode(json_str.encode('utf-8'))
    return b64_bytes.decode('utf-8').rstrip('=')

def normalize_scheme(raw_scheme: str) -> str:
    s = raw_scheme.lower()
    if s == "x402-direct": return SchemeType.lnc_evm_transfer.value
    if s == "x402-solana": return SchemeType.lnc_solana_transfer.value
    if s == "x402-relay":  return SchemeType.lnc_evm_relay.value
    if s == "x402": return SchemeType.x402.value
    return raw_scheme

def parse_legacy_header(header_val: str) -> ParsedChallenge:
    params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', header_val)}
    return ParsedChallenge(
        scheme=params.get("scheme", "unknown"),
        network=params.get("network", "unknown"),
        amount=float(params.get("amount", 0)),
        asset=params.get("asset", "USDC"),
        parameters=params,
        source=ChallengeSource.LEGACY_CUSTOM,
        raw_header=header_val
    )

# P0-B: 厳密なNetwork + Token照合辞書
# 💡 修正: SolanaのGenesis HashとMint AddressはCase-Sensitiveなため元の値を維持
TRUSTED_TOKENS = {
    "eip155:8453_0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {"asset": "USDC", "decimals": 6},
    "eip155:137_0x2791bca1f2de4661ed88a30c99a7a9449aa84174": {"asset": "USDC", "decimals": 6},
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp_EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {"asset": "USDC", "decimals": 6},
}

# 過去のテストコードとの互換性維持のための定数
SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

def parse_www_authenticate(auth_header: str, source: ChallengeSource = ChallengeSource.STANDARD_WWW) -> ParsedChallenge:
    parts = auth_header.strip().split(None, 1)
    scheme = parts[0] if parts else ""
    params: Dict[str, Any] = {}
    auth_params_valid = True
    if len(parts) > 1:
        params, auth_params_valid = _parse_http_auth_params(parts[1])

    draft_shape = "unknown-payment-shape"
    payment_method = "unknown"
    payment_intent = "unknown"
    request_b64_present = False
    decoded_request_valid = False
    parsed_amount = 0.0
    parsed_asset = "SATS"
    invoice_msats = None
    is_payment_family = scheme in ["Payment", "MPP"]
    request_json: Dict[str, Any] = {}
    method_details: Dict[str, Any] = {}
    request_json_valid = True
    request_json_duplicate = False
    method_details_valid = True

    if is_payment_family:
        if "invoice" in params and "request" not in params:
            draft_shape = "legacy-mpp-flat"

        if "request" in params:
            request_b64_present = True
            request_json, request_json_valid, request_json_duplicate = (
                _decode_mpp_request(params["request"])
            )
            if request_json_valid:
                params["request_json"] = request_json
                details_present, details_value, details_unique = _casefold_json_field(
                    request_json, "methodDetails"
                )
                if not details_unique:
                    method_details_valid = False
                elif details_present:
                    if isinstance(details_value, dict):
                        method_details = details_value
                    else:
                        method_details_valid = False

                decoded_request_valid = (
                    bool(request_json)
                    and not request_json_duplicate
                    and method_details_valid
                )

        method_present, method_value, method_consistent, _ = (
            _resolve_mpp_control_field(
                params, request_json, method_details, "method"
            )
        )
        intent_present, intent_value, intent_consistent, intent_values = (
            _resolve_mpp_control_field(
                params, request_json, method_details, "intent"
            )
        )

        method_supported = (
            not method_present
            or (method_consistent and method_value == "lightning")
        )
        intent_supported = (
            not intent_present
            or (
                intent_consistent
                and intent_value in {"charge", "session"}
            )
        )
        control_fields_valid = (
            method_consistent
            and intent_consistent
            and method_supported
            and intent_supported
        )

        if method_present and method_value is not _MISSING:
            payment_method = method_value
        if "session" in intent_values:
            # Never let an outer charge declaration mask a nested session intent.
            payment_intent = "session"
        elif intent_present and intent_value is not _MISSING:
            payment_intent = intent_value
        elif draft_shape == "legacy-mpp-flat":
            payment_intent = "charge"

        if request_b64_present:
            id_value = params.get("id", _MISSING)
            id_valid = (
                id_value is _MISSING
                or (isinstance(id_value, str) and bool(id_value.strip()))
            )
            has_required = all(
                key in params for key in ["id", "method", "intent", "request"]
            )
            decoded_request_valid = (
                decoded_request_valid
                and auth_params_valid
                and id_valid
                and control_fields_valid
            )
            if decoded_request_valid:
                draft_shape = (
                    "payment-auth-draft"
                    if has_required
                    else "payment-auth-draft-partial"
                )
            else:
                draft_shape = "payment-auth-draft-invalid-request"

    invoice_present = "invoice" in params
    invoice_value = params.get("invoice")
    invoice_consistent = True
    currency_present = False
    currency_value = _MISSING
    currency_consistent = True
    amount_present = False
    amount_value = _MISSING
    amount_consistent = True

    if is_payment_family:
        invoice_present, invoice_value, invoice_consistent = _resolve_mpp_field(
            params, request_json, method_details, "invoice"
        )
        currency_present, currency_value, currency_consistent = _resolve_mpp_field(
            params, request_json, method_details, "currency"
        )
        amount_present, amount_value, amount_consistent = _resolve_mpp_field(
            params, request_json, method_details, "amount"
        )
        if invoice_present:
            params["invoice"] = invoice_value

        if (
            not auth_params_valid
            or (request_b64_present and not request_json_valid)
            or request_json_duplicate
            or not method_details_valid
            or not control_fields_valid
            or not invoice_consistent
        ):
            invoice_msats = -1
        elif not currency_consistent:
            invoice_msats = -4
        elif not amount_consistent:
            invoice_msats = -3
        elif currency_present:
            normalized_currency = _normalize_mpp_currency(currency_value)
            if normalized_currency is None:
                invoice_msats = -4
            else:
                parsed_asset = normalized_currency

        if payment_method == "unknown" and isinstance(invoice_value, str):
            if invoice_value.lower().startswith(("lnbc", "lntb")):
                payment_method = "lightning"
    elif not auth_params_valid:
        invoice_msats = -1

    inv_str = invoice_value if invoice_present else None
    if invoice_msats is None and (
        not isinstance(inv_str, str)
        or not inv_str
        or inv_str != inv_str.strip()
    ):
        invoice_msats = -1

    if invoice_msats is None:
        try:
            invoice_msats = decode_bolt11_amount_msats(inv_str)
            if (
                isinstance(invoice_msats, bool)
                or not isinstance(invoice_msats, int)
                or invoice_msats <= 0
            ):
                raise ValueError("invalid invoice amount")
            parsed_amount = float(Decimal(str(invoice_msats)) / Decimal("1000"))
        except Exception:
            invoice_msats = -1

    if is_payment_family and amount_present and invoice_msats > 0:
        declared_amount = _canonical_mpp_amount_decimal(amount_value)
        if declared_amount is None:
            invoice_msats = -3
        else:
            actual_sats = Decimal(invoice_msats) / Decimal("1000")
            if declared_amount != actual_sats:
                invoice_msats = -2

    pc = ParsedChallenge(
        scheme=scheme,
        network="Lightning",
        amount=parsed_amount,
        asset=parsed_asset,
        parameters=params,
        source=source,
        raw_header=auth_header,
        draft_shape=draft_shape,
        payment_method=payment_method,
        payment_intent=payment_intent,
        request_b64_present=request_b64_present,
        decoded_request_valid=decoded_request_valid
    )
    pc._invoice_msats = invoice_msats
    if invoice_msats is not None and invoice_msats > 0:
        atomic_amount = str(invoice_msats)
        canonical_req = CanonicalPaymentRequirement(
            scheme=scheme,
            network="Lightning",
            chain_id=None,
            asset="SATS",
            token_address_or_mint="",
            decimals=3,
            atomic_amount=atomic_amount,
            human_amount_decimal=Decimal(invoice_msats) / Decimal("1000"),
            pay_to="",
            source_origin="bolt11_invoice"
        )
        pc._atomic_amount = atomic_amount
        pc._canonical_requirement = canonical_req
    return pc

def _safe_float(val) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0

def _normalize_network(net_str: str) -> str:
    """Networkの大文字小文字を安全に正規化（SolanaのBase58ハッシュはそのまま保持する）"""
    if not net_str: return "unknown"
    parts = net_str.split(":", 1)
    if len(parts) == 2:
        if parts[0].lower() == "eip155":
            return f"eip155:{parts[1].lower()}"
        elif parts[0].lower() == "solana":
            return f"solana:{parts[1]}"
    return net_str.lower()


def _response_request_binding(response: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    request = getattr(response, "request", None)
    if request is None:
        return None, None, None
    request_url = getattr(request, "url", None)
    request_method = getattr(request, "method", None)
    request_headers = getattr(request, "headers", {}) or {}
    idempotency_key = None
    try:
        for key, value in request_headers.items():
            if str(key).lower() == "idempotency-key":
                idempotency_key = str(value)
                break
    except Exception:
        pass
    return (
        str(request_url) if request_url is not None else None,
        str(request_method) if request_method is not None else None,
        idempotency_key,
    )


def _canonical_display_amount(requirement: Dict[str, Any]) -> Decimal:
    return Decimal(requirement["amount_atomic"]) / (
        Decimal(10) ** int(requirement["decimals"])
    )


def _validate_paid_surface_display_fields(
    option: Dict[str, Any], requirement: Dict[str, Any]
) -> None:
    """Legacy display fields are optional but can never contradict canonical."""
    mismatches = []
    comparisons = {
        "settlement_rail": requirement["rail"],
        "rail": requirement["rail"],
        "authorization_scheme": requirement["authorization_scheme"],
        "network": requirement["network"],
        "decimals": requirement["decimals"],
        "amount_atomic": requirement["amount_atomic"],
        "pay_to": requirement["pay_to"],
        "payTo": requirement["pay_to"],
    }
    for field, expected in comparisons.items():
        if field in option and option[field] != expected:
            mismatches.append(field)

    if "asset" in option:
        displayed_asset = option["asset"]
        expected_asset = "SATS" if requirement["asset_identifier"] == "lightning:sats" else None
        if expected_asset is None or displayed_asset != expected_asset:
            mismatches.append("asset")
    if "amount" in option:
        raw_amount = option["amount"]
        if isinstance(raw_amount, bool) or isinstance(raw_amount, float):
            mismatches.append("amount")
        else:
            try:
                display_amount = Decimal(str(raw_amount))
            except InvalidOperation:
                mismatches.append("amount")
            else:
                if display_amount != _canonical_display_amount(requirement):
                    mismatches.append("amount")
    if mismatches:
        raise PaymentContractError(
            "Paid-surface display fields contradict canonical requirement: "
            + ", ".join(sorted(set(mismatches)))
        )


def _parse_paid_surface_challenge(
    response: Any,
    body: Dict[str, Any],
    *,
    allowed_networks: Optional[list],
    now: int,
    logical_request_url: Optional[str] = None,
    logical_request_method: Optional[str] = None,
    logical_idempotency_key: Optional[str] = None,
) -> ParsedChallenge:
    options = body.get("accepted_payments")
    if not isinstance(options, list) or not options:
        raise PaymentChallengeError(
            "Fail-Closed: paid-surface challenge has no accepted payment options."
        )

    response_url, response_method, response_idempotency_key = (
        _response_request_binding(response)
    )
    request_url = logical_request_url or response_url
    request_method = logical_request_method or response_method
    request_idempotency_key = (
        logical_idempotency_key
        if logical_idempotency_key is not None
        else response_idempotency_key
    )
    if not request_url or not request_method:
        raise PaymentChallengeError(
            "Fail-Closed: paid-surface challenge is missing its actual request binding."
        )

    normalized_allowed = None
    if allowed_networks is not None:
        normalized_allowed = {str(value).lower() for value in allowed_networks}

    executable_seen = False
    last_error = None
    for option in options:
        if not isinstance(option, dict):
            last_error = "payment option is not an object"
            continue
        raw_requirement = option.get("canonical_requirement")
        credential = option.get("credential_challenge")
        if raw_requirement is None or credential is None:
            continue
        executable_seen = True
        try:
            requirement = verify_canonical_payment_requirement(raw_requirement)
            verify_request_binding(
                requirement, request_url=request_url, method=request_method
            )
            verify_requirement_expiry(requirement, now=now)
            if (
                request_idempotency_key is None
                or requirement["idempotency_key"] != request_idempotency_key
            ):
                raise PaymentContractError(
                    "Canonical idempotency key does not match the actual request."
                )
            if normalized_allowed is not None and requirement["network"].lower() not in normalized_allowed:
                continue
            _validate_paid_surface_display_fields(option, requirement)

            if requirement["rail"] != "l402":
                raise PaymentContractError(
                    "Selected canonical payment rail is not executable by this path."
                )
            if not isinstance(credential, dict) or set(credential) != {
                "type", "authorization_scheme", "invoice", "macaroon"
            }:
                raise PaymentContractError(
                    "L402 credential_challenge has an invalid shape."
                )
            if credential.get("type") != "l402" or credential.get("authorization_scheme") != "L402":
                raise PaymentContractError(
                    "L402 credential_challenge scheme is invalid."
                )
            invoice = credential.get("invoice")
            macaroon = credential.get("macaroon")
            if (
                not isinstance(invoice, str)
                or not invoice
                or invoice.startswith("<")
                or sha256_prefixed(invoice) != requirement["credential_payload_hash"]
            ):
                raise PaymentContractError(
                    "L402 invoice does not match credential_payload_hash."
                )
            if (
                not isinstance(macaroon, str)
                or macaroon != macaroon.strip()
                or macaroon.startswith("<")
                or re.fullmatch(r"[A-Za-z0-9+/_=-]+", macaroon) is None
            ):
                raise PaymentContractError("L402 macaroon is invalid.")
            validate_l402_macaroon_structure(
                macaroon, canonical_requirement=requirement
            )

            metadata = decode_bolt11_payment_metadata(invoice)
            verify_l402_metadata(requirement, metadata, now=now)

            auth_header = response.headers.get("WWW-Authenticate", "")
            if auth_header:
                parts = auth_header.strip().split(None, 1)
                if len(parts) != 2 or parts[0] != "L402":
                    raise PaymentContractError(
                        "WWW-Authenticate contradicts canonical L402 challenge."
                    )
                auth_params, valid = _parse_http_auth_params(parts[1])
                if (
                    not valid
                    or set(auth_params) != {
                        "invoice", "macaroon", "id", "requirement_hash"
                    }
                    or auth_params.get("invoice") != invoice
                    or auth_params.get("macaroon") != macaroon
                    or auth_params.get("id") != requirement["challenge_id"]
                    or auth_params.get("requirement_hash") != requirement["requirement_hash"]
                ):
                    raise PaymentContractError(
                        "WWW-Authenticate does not match the body L402 challenge."
                    )

            payment_required = response.headers.get("PAYMENT-REQUIRED")
            if payment_required:
                legacy_params, valid = _parse_http_auth_params(payment_required)
                expected_legacy = {
                    "network": requirement["network"],
                    "amount_atomic": requirement["amount_atomic"],
                    "decimals": str(requirement["decimals"]),
                    "asset": requirement["asset_identifier"],
                    "id": requirement["challenge_id"],
                    "requirement_hash": requirement["requirement_hash"],
                }
                if not valid or legacy_params != expected_legacy:
                    raise PaymentContractError(
                        "PAYMENT-REQUIRED contradicts canonical L402 challenge."
                    )
            x402_payment_required = response.headers.get("x-402-payment-required")
            if x402_payment_required is not None:
                expected_x402 = (
                    f"amount_atomic={requirement['amount_atomic']}; "
                    f"asset={requirement['asset_identifier']}; "
                    f"network={requirement['network']}; "
                    f"requirement_hash={requirement['requirement_hash']}"
                )
                if x402_payment_required != expected_x402:
                    raise PaymentContractError(
                        "x-402-payment-required contradicts canonical L402 challenge."
                    )
            returned_idempotency = response.headers.get("Idempotency-Key")
            if (
                returned_idempotency is not None
                and returned_idempotency != requirement["idempotency_key"]
            ):
                raise PaymentContractError(
                    "Response idempotency key contradicts canonical requirement."
                )

            parsed = ParsedChallenge(
                scheme="L402",
                network=requirement["network"],
                amount=float(_canonical_display_amount(requirement)),
                asset="SATS",
                parameters={
                    "invoice": invoice,
                    "macaroon": macaroon,
                    "challenge_id": requirement["challenge_id"],
                    "payment_id": requirement["payment_id"],
                    "idempotency_key": requirement["idempotency_key"],
                    "requirement_hash": requirement["requirement_hash"],
                    "_selection_reason": "canonical_paid_surface_v1",
                    "_raw_accepted": option,
                },
                source=ChallengeSource.BODY_CHALLENGE,
                raw_header=auth_header or None,
                draft_shape="ln_church.paid_surface_challenge.v1",
                payment_method="lightning",
                payment_intent=str(
                    (body.get("surface") or {}).get("payment_intent", "charge")
                ),
            )
            parsed._invoice_msats = int(requirement["amount_atomic"])
            parsed._atomic_amount = requirement["amount_atomic"]
            parsed._canonical_requirement = requirement
            return parsed
        except (PaymentContractError, ValueError, TypeError) as exc:
            last_error = str(exc)

    if not executable_seen:
        # Preserve inspectability of the deployed legacy shape, but deliberately
        # leave it without a canonical requirement so execution fails closed.
        first = options[0] if isinstance(options[0], dict) else {}
        return ParsedChallenge(
            scheme=str(first.get("settlement_rail", "unknown")),
            network="unknown",
            amount=_safe_float(first.get("amount", 0)),
            asset=str(first.get("asset", "unknown")),
            parameters={"_selection_reason": "missing_canonical_requirement"},
            source=ChallengeSource.BODY_CHALLENGE,
            draft_shape="ln_church.paid_surface_challenge.v1-inspect-only",
        )
    raise PaymentChallengeError(
        "Fail-Closed: no executable canonical paid-surface option"
        + (f" ({last_error})" if last_error else ".")
    )

def parse_challenge_from_response(
    response: httpx.Response,
    expected_asset: str = "USDC",
    expected_chain_id: Optional[str] = None,
    allowed_networks: Optional[list] = None,
    prefer_svm: bool = False,
    now: Optional[int] = None,
    request_url: Optional[str] = None,
    request_method: Optional[str] = None,
    request_idempotency_key: Optional[str] = None,
) -> ParsedChallenge:
    h = response.headers

    try:
        body = response.json()
    except Exception:
        body = None
    if (
        isinstance(body, dict)
        and body.get("schema_version") == "ln_church.paid_surface_challenge.v1"
    ):
        return _parse_paid_surface_challenge(
            response,
            body,
            allowed_networks=allowed_networks,
            now=int(time.time()) if now is None else now,
            logical_request_url=request_url,
            logical_request_method=request_method,
            logical_idempotency_key=request_idempotency_key,
        )

    auth_h = h.get("WWW-Authenticate", "")
    pay_req = h.get("payment-required") or h.get("x-payment-required") or h.get("PAYMENT-REQUIRED")

    if auth_h.upper().startswith(("L402", "PAYMENT", "MPP")):
        return parse_www_authenticate(auth_h, source=ChallengeSource.STANDARD_WWW)

    if not pay_req and auth_h.upper().startswith("X402"):
        return parse_www_authenticate(auth_h, source=ChallengeSource.STANDARD_WWW)

    payload = None
    source_type = ChallengeSource.STANDARD_X402
    raw_header_val = pay_req

    if pay_req:
        payload = b64url_decode_json(pay_req)
        if not payload:
            params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', pay_req)}
            if params:
                return ParsedChallenge(
                    scheme=params.get("scheme", "x402"),
                    network=params.get("network", "unknown"),
                    amount=_safe_float(params.get("amount", 0)),
                    asset=params.get("asset", expected_asset),
                    parameters=params,
                    source=source_type,
                    raw_header=pay_req
                )

    if not payload:
        try:
            body = response.json()
            if isinstance(body, dict):
                if "challenge" in body:
                    c = body["challenge"]
                    return ParsedChallenge(
                        scheme=c.get("scheme", "unknown"),
                        network=c.get("network", "unknown"),
                        amount=_safe_float(c.get("amount", 0)),
                        asset=c.get("asset", "unknown"),
                        parameters=c.get("parameters", {}),
                        source=ChallengeSource.BODY_CHALLENGE
                    )
                elif any(k in body for k in ["accepts", "x402Version", "paymentRequirements", "resource"]):
                    payload = body
                    source_type = ChallengeSource.BODY_CHALLENGE
                    raw_header_val = None
        except Exception:
            pass

    if payload:
        accepted_params = {}
        selected_accept = None
        all_accepted = []
        canonical_req = None

        if "accepts" in payload and isinstance(payload["accepts"], list):
            valid_accepts = payload["accepts"]
            all_accepted = valid_accepts

            selection_reason = "not_selected"

            if allowed_networks is not None:
                normalized_allowed = [_normalize_network(n) for n in allowed_networks]
                valid_accepts = [opt for opt in valid_accepts if _normalize_network(opt.get("network", "")) in normalized_allowed]
                if not valid_accepts:
                    selection_reason = "no_allowed_network_match"
                    selected_accept = None

            if selection_reason != "no_allowed_network_match":
                if expected_chain_id:
                    target_network = f"eip155:{expected_chain_id}"
                    selected_accept = next((opt for opt in valid_accepts if _normalize_network(str(opt.get("network", ""))) == target_network.lower()), None)
                    if selected_accept: selection_reason = "expected_chain_id"

                if not selected_accept and prefer_svm:
                    selected_accept = next((opt for opt in valid_accepts if str(opt.get("network", "")).lower().startswith("solana:")), None)
                    if selected_accept: selection_reason = "prefer_svm"

                if not selected_accept and len(valid_accepts) > 0:
                    selected_accept = valid_accepts[0]
                    selection_reason = "first_acceptable"
                elif not selected_accept and allowed_networks is None and len(payload["accepts"]) > 0:
                    selected_accept = payload["accepts"][0]
                    selection_reason = "fallback_first_presented"

            if selected_accept:
                net_str = _normalize_network(str(selected_accept.get("network", "unknown")))
                chain_id = None
                if net_str.startswith("eip155:"):
                    chain_component = net_str.split(":", 1)[1]
                    if re.fullmatch(r"[1-9][0-9]*", chain_component):
                        chain_id = int(chain_component)
                    else:
                        selection_reason = "invalid_network"

                if payload.get("network") and selected_accept.get("network"):
                    if _normalize_network(payload.get("network")) != _normalize_network(selected_accept.get("network")):
                        selection_reason = "outer_inner_mismatch"
                raw_asset = selected_accept.get("asset", expected_asset)
                logical_asset = selected_accept.get("symbol") or payload.get("asset") or expected_asset
                raw_amount = selected_accept.get("amount", 0)
                atomic_amt = _canonical_positive_integer_string(raw_amount)
                if atomic_amt is None:
                    selection_reason = "invalid_atomic_amount"

                extracted_token = raw_asset if isinstance(raw_asset, str) and (raw_asset.startswith("0x") or len(raw_asset) > 30) else ""

                if net_str.startswith("solana:"):
                    lookup_key = f"{net_str}_{extracted_token}"
                else:
                    lookup_key = f"{net_str}_{extracted_token.lower()}"

                known_meta = TRUSTED_TOKENS.get(lookup_key)

                if selected_accept.get("scheme", "exact") == "exact":
                    if not known_meta:
                        selection_reason = "unknown_token_contract"
                        human_amount = 0.0
                        decimals = 0
                        human_amount_dec = Decimal("0")
                    else:
                        logical_asset = known_meta["asset"]
                        decimals = known_meta["decimals"]

                        declared_symbol = selected_accept.get("symbol")
                        declared_decimals = selected_accept.get("decimals")

                        if declared_symbol and declared_symbol.upper() != logical_asset.upper():
                            selection_reason = "unknown_token_contract"
                        if declared_decimals is not None and int(declared_decimals) != decimals:
                            selection_reason = "unknown_token_contract"

                        try:
                            if atomic_amt is None:
                                raise InvalidOperation
                            human_amount_dec = Decimal(atomic_amt) / Decimal(10 ** decimals)
                            human_amount = float(human_amount_dec)
                        except (InvalidOperation, TypeError, ValueError):
                            human_amount_dec = Decimal("0")
                            human_amount = 0.0
                else:
                    decimals = payload.get("decimals") or selected_accept.get("decimals") or 6
                    try:
                        if atomic_amt is None:
                            raise InvalidOperation
                        human_amount_dec = Decimal(atomic_amt) / Decimal(10 ** decimals)
                        human_amount = float(human_amount_dec)
                    except (InvalidOperation, TypeError, ValueError):
                        human_amount_dec = Decimal("0")
                        human_amount = 0.0

                if atomic_amt is not None:
                    canonical_req = CanonicalPaymentRequirement(
                        scheme=selected_accept.get("scheme", "exact"),
                        network=net_str,
                        chain_id=chain_id,
                        asset=logical_asset,
                        token_address_or_mint=extracted_token,
                        decimals=decimals,
                        atomic_amount=atomic_amt,
                        human_amount_decimal=human_amount_dec,
                        pay_to=selected_accept.get("payTo", ""),
                        source_origin="accepts_array"
                    )

                accepted_params = {
                    "scheme": selected_accept.get("scheme", "exact"),
                    "network": net_str,
                    "amount": human_amount,
                    "atomic_amount": atomic_amt,
                    "asset": logical_asset,
                    "payTo": selected_accept.get("payTo", ""),
                    "token_address": extracted_token,
                    "decimals": decimals,
                    "_raw_accepted": selected_accept,
                    "_all_accepted": all_accepted,
                    "_raw_resource": payload.get("resource", {}),
                    "_raw_extensions": payload.get("extensions"),
                    "_selection_reason": selection_reason,
                    "_raw_amount": raw_amount
                }

                for k, v in payload.get("parameters", {}).items():
                    if k not in accepted_params: accepted_params[k] = v
                for k, v in selected_accept.get("parameters", {}).items():
                    if k not in accepted_params: accepted_params[k] = v
                for k, v in selected_accept.get("extra", {}).items():
                    if k not in accepted_params: accepted_params[k] = v

            elif selection_reason == "no_allowed_network_match":
                accepted_params = {
                    "_all_accepted": all_accepted,
                    "_selection_reason": selection_reason
                }

        params = {
            "network": payload.get("network") or accepted_params.get("network", "unknown"),
            "amount": payload.get("amount") or accepted_params.get("amount", 0),
            "asset": accepted_params.get("asset") or payload.get("asset") or expected_asset,
            "destination": payload.get("destination") or accepted_params.get("payTo", ""),
            "payTo": payload.get("payTo") or accepted_params.get("payTo", ""),
            "token_address": accepted_params.get("token_address") or payload.get("token_address") or "",
            "decimals": payload.get("decimals") or (selected_accept.get("decimals") if selected_accept else None) or accepted_params.get("decimals"),
            "reference": payload.get("reference") or (selected_accept.get("extra", {}).get("reference") if selected_accept else None) or accepted_params.get("reference"),
            "challenge": payload.get("challenge", ""),
            "_raw_accepted": accepted_params.get("_raw_accepted"),
            "_all_accepted": accepted_params.get("_all_accepted", []),
            "_raw_resource": accepted_params.get("_raw_resource"),
            "_raw_extensions": accepted_params.get("_raw_extensions"),
            "_selection_reason": accepted_params.get("_selection_reason", "unknown"),
            "_raw_amount": accepted_params.get("_raw_amount"),
            "_raw_outer_network": payload.get("network"),
            "_raw_outer_chain_id": payload.get("chainId"),
            "_raw_outer_chain_id_alias": payload.get("chain_id"),
            "_raw_outer_asset": payload.get("asset"),
            "_raw_outer_contract": payload.get("contract"),
            "_raw_outer_token_address": payload.get("token_address"),
            "_raw_outer_amount": payload.get("amount"),
            "_raw_outer_destination": payload.get("destination"),
            "_raw_outer_pay_to": payload.get("payTo"),
            "_raw_outer_parameters": payload.get("parameters"),
        }

        for k, v in accepted_params.items():
            if k not in params:
                params[k] = v

        params["amount"] = accepted_params.get("amount", params["amount"])

        pc = ParsedChallenge(
            scheme=accepted_params.get("scheme") or payload.get("scheme") or "x402",
            network=params["network"],
            amount=_safe_float(params["amount"]),
            asset=params["asset"],
            parameters=params,
            source=source_type,
            raw_header=raw_header_val
        )
        if canonical_req is not None:
            pc._atomic_amount = canonical_req.atomic_amount
            pc._canonical_requirement = canonical_req
        return pc

    if "x-402-payment-required" in h:
        return parse_legacy_header(h["x-402-payment-required"])

    raise PaymentChallengeError("No valid 402 challenge found in headers or body.")
