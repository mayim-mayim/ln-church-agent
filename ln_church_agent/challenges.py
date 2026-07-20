import base64
import json
import math
import re
import time
import httpx
from typing import Any, Dict, Optional, Tuple
from decimal import Decimal, InvalidOperation

from .models import ParsedChallenge, ChallengeSource, SchemeType, CanonicalPaymentRequirement
from .exceptions import NoValidPaymentChallengeError, PaymentChallengeError
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
    if type(raw_params) is not str or any(
        (ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F
        for char in raw_params
    ):
        return params, False
    valid = True
    pos = 0
    length = len(raw_params)

    while pos < length:
        while pos < length and raw_params[pos] in " \t":
            pos += 1
        if pos >= length:
            break
        if raw_params[pos] == ",":
            return params, False

        name_match = _AUTH_PARAM_NAME.match(raw_params, pos)
        if name_match is None:
            return params, False
        name = name_match.group(0)
        pos = name_match.end()
        while pos < length and raw_params[pos] in " \t":
            pos += 1
        if pos >= length or raw_params[pos] != "=":
            return params, False
        pos += 1
        while pos < length and raw_params[pos] in " \t":
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
            value_match = _AUTH_PARAM_NAME.match(raw_params, pos)
            if value_match is None:
                return params, False
            value = value_match.group(0)
            pos = value_match.end()

        normalized_name = name.casefold()
        if normalized_name in params:
            valid = False
        else:
            params[normalized_name] = value

        while pos < length and raw_params[pos] in " \t":
            pos += 1
        if pos >= length:
            break
        if raw_params[pos] != ",":
            return params, False
        pos += 1
        cursor = pos
        while cursor < length and raw_params[cursor] in " \t":
            cursor += 1
        if cursor >= length or raw_params[cursor] == ",":
            return params, False

    return params, valid


def _strict_b64url_decode(value: str) -> bytes:
    """Decode one canonical padded or unpadded Base64URL value."""
    if (
        type(value) is not str
        or not value
        or re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value) is None
    ):
        raise ValueError("invalid Base64URL")

    core = value.rstrip("=")
    remainder = len(core) % 4
    if remainder == 1:
        raise ValueError("invalid Base64URL length")
    required_padding = {0: 0, 2: 2, 3: 1}[remainder]
    supplied_padding = len(value) - len(core)
    if supplied_padding not in {0, required_padding}:
        raise ValueError("invalid Base64URL padding")
    if supplied_padding and required_padding == 0:
        raise ValueError("unnecessary Base64URL padding")

    canonical_padded = core + ("=" * required_padding)
    decoded = base64.b64decode(
        canonical_padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )
    reencoded = base64.urlsafe_b64encode(decoded).decode("ascii")
    expected = reencoded if supplied_padding else reencoded.rstrip("=")
    if value != expected:
        raise ValueError("non-canonical Base64URL")
    return decoded


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError("non-standard JSON constant")


def _decode_mpp_request(value: str) -> Tuple[Dict[str, Any], bool, bool]:
    """Decode request JSON and retain case-insensitive duplicate detection."""
    try:
        decoded_bytes = _strict_b64url_decode(value)

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
            decoded_bytes.decode("utf-8"),
            object_pairs_hook=checked_object,
            parse_constant=_reject_json_constant,
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


_SUPPORTED_ACCEPTS_SCHEMES = frozenset({
    "exact",
    "x402",
    "batch-settlement",
    "auth-capture",
    "x402-direct",
    "x402-solana",
    "x402-relay",
    "lnc-evm-transfer",
    "lnc-solana-transfer",
    "lnc-evm-relay",
})
_SUPPORTED_FLAT_X402_SCHEMES = frozenset({
    "x402",
    "x402-direct",
    "x402-solana",
    "x402-relay",
    "lnc-evm-transfer",
    "lnc-solana-transfer",
    "lnc-evm-relay",
})
_SUPPORTED_DIRECT_PAYMENT_SCHEMES = (
    _SUPPORTED_FLAT_X402_SCHEMES
    | frozenset({"exact", "batch-settlement", "auth-capture"})
)
_SUPPORTED_PAYMENT_AUTH_SCHEMES = frozenset({"l402", "mpp", "payment", "x402"})
_NON_PAYMENT_AUTH_SCHEMES = frozenset({"basic", "bearer", "digest", "negotiate"})


class _UnselectedPolicyAmountView:
    """Amount-only view that cannot be promoted into a signer requirement."""

    __slots__ = (
        "network",
        "decimals",
        "atomic_amount",
        "human_amount_decimal",
    )

    def __init__(
        self,
        *,
        network: str,
        decimals: int,
        atomic_amount: str,
        human_amount_decimal: Decimal,
    ) -> None:
        self.network = network
        self.decimals = decimals
        self.atomic_amount = atomic_amount
        self.human_amount_decimal = human_amount_decimal


def _is_nonempty_text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _is_finite_number(value: Any, *, positive: bool) -> bool:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    if type(value) is str and value != value.strip():
        return False
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return False
    if not number.is_finite():
        return False
    try:
        float_value = float(number)
        if not math.isfinite(float_value):
            return False
    except (OverflowError, ValueError):
        return False
    return (
        number > 0 and float_value > 0
        if positive
        else number >= 0
    )


def _is_supported_x402_network(value: Any) -> bool:
    """Return whether a network is explicit enough for an executable x402 rail."""
    if not _is_nonempty_text(value) or value != value.strip():
        return False
    if re.fullmatch(r"eip155:[1-9][0-9]*", value):
        return True
    return (
        re.fullmatch(
            r"solana:[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?",
            value,
        )
        is not None
    )


def _scheme_matches_network(scheme: str, network: str) -> bool:
    evm_only = {
        "x402-direct",
        "x402-relay",
        "lnc-evm-transfer",
        "lnc-evm-relay",
    }
    solana_only = {"x402-solana", "lnc-solana-transfer"}
    if scheme in evm_only:
        return network.startswith("eip155:")
    if scheme in solana_only:
        return network.startswith("solana:")
    return True


def _raise_malformed_payment_challenge() -> None:
    """Raise one fixed parser-domain error without reflecting peer input."""
    raise PaymentChallengeError("Malformed payment challenge.")


def _www_authenticate_schemes(value: str) -> Tuple[str, ...]:
    """Return challenge schemes without treating quoted text as syntax."""
    masked = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            masked.append(" ")
        elif char == "\\" and quoted:
            escaped = True
            masked.append(" ")
        elif char == '"':
            quoted = not quoted
            masked.append(" ")
        elif quoted:
            masked.append(" ")
        else:
            masked.append(char)

    unquoted = "".join(masked)
    schemes = []
    for match in re.finditer(
        r"(?:^|,)\s*([!#$%&'*+\-.^_`|~0-9A-Za-z]+)",
        unquoted,
    ):
        cursor = match.end(1)
        while cursor < len(unquoted) and unquoted[cursor].isspace():
            cursor += 1
        if cursor < len(unquoted) and unquoted[cursor] == "=":
            continue
        schemes.append(match.group(1).casefold())
    return tuple(schemes)


def _validate_body_challenge_marker(value: Any) -> Dict[str, Any]:
    """Validate the deployed body-challenge contract before defaulting."""
    if type(value) is not dict or not value:
        _raise_malformed_payment_challenge()
    if not _is_nonempty_text(value.get("scheme")):
        _raise_malformed_payment_challenge()
    if not _is_nonempty_text(value.get("asset")):
        _raise_malformed_payment_challenge()
    if "amount" not in value or not _is_finite_number(
        value["amount"], positive=False
    ):
        _raise_malformed_payment_challenge()
    if "network" in value and not _is_nonempty_text(value["network"]):
        _raise_malformed_payment_challenge()
    if "parameters" in value and type(value["parameters"]) is not dict:
        _raise_malformed_payment_challenge()

    scheme = value["scheme"]
    normalized_scheme = scheme.casefold()
    parameters = value.get("parameters", {})
    legacy_unmapped_shape = (
        set(value) == {"scheme", "network", "amount", "asset", "parameters"}
        and value["network"] == "unknown"
        and type(value["amount"]) is int
        and value["amount"] == 0
        and value["asset"] == "unknown"
        and parameters == {}
    )

    if "scheme" in parameters and parameters["scheme"] != scheme:
        _raise_malformed_payment_challenge()
    if "network" in parameters:
        nested_network = parameters["network"]
        if not _is_nonempty_text(nested_network) or (
            "network" in value
            and _normalize_network(nested_network)
            != _normalize_network(value["network"])
        ):
            _raise_malformed_payment_challenge()
    for chain_field in ("chainId", "chain_id"):
        if chain_field in parameters:
            chain_value = parameters[chain_field]
            if (
                isinstance(chain_value, bool)
                or not (
                    (type(chain_value) is int and chain_value > 0)
                    or (
                        type(chain_value) is str
                        and re.fullmatch(r"[1-9][0-9]*", chain_value)
                    )
                )
                or "network" not in value
                or not _normalize_network(value["network"]).startswith("eip155:")
                or _normalize_network(value["network"]).split(":", 1)[1]
                != str(chain_value)
            ):
                _raise_malformed_payment_challenge()
    if "asset" in parameters and parameters["asset"] != value["asset"]:
        _raise_malformed_payment_challenge()
    if "amount" in parameters and (
        not _is_finite_number(parameters["amount"], positive=True)
        or Decimal(str(parameters["amount"])) != Decimal(str(value["amount"]))
    ):
        _raise_malformed_payment_challenge()
    for decimals_source in (value, parameters):
        if "decimals" in decimals_source:
            decimals = decimals_source["decimals"]
            if (
                isinstance(decimals, bool)
                or type(decimals) is not int
                or not 0 <= decimals <= 255
            ):
                _raise_malformed_payment_challenge()
    if (
        "decimals" in value
        and "decimals" in parameters
        and value["decimals"] != parameters["decimals"]
    ):
        _raise_malformed_payment_challenge()
    nested_tokens = [
        parameters[field]
        for field in ("contract", "token_address", "token", "mint")
        if field in parameters
    ]
    if nested_tokens:
        if (
            any(not _is_nonempty_text(token) for token in nested_tokens)
            or any(token != nested_tokens[0] for token in nested_tokens[1:])
        ):
            _raise_malformed_payment_challenge()
        outer_asset = value["asset"]
        if (
            _is_nonempty_text(outer_asset)
            and (outer_asset.startswith("0x") or len(outer_asset) > 30)
            and any(token != outer_asset for token in nested_tokens)
        ):
            _raise_malformed_payment_challenge()

    # Preserve the deployed body-L402 observation contract while preventing a
    # zero/default challenge from becoming an executable rail.
    if normalized_scheme == "l402":
        if scheme != "L402" or value["asset"] != "SATS" or not _is_finite_number(
            value["amount"], positive=True
        ):
            _raise_malformed_payment_challenge()
    elif normalized_scheme == "mpp":
        if (
            scheme != "MPP"
            or value["asset"] != "SATS"
            or not _is_finite_number(value["amount"], positive=True)
            or not _is_nonempty_text(parameters.get("invoice"))
        ):
            _raise_malformed_payment_challenge()
    elif normalized_scheme in {"x402", "exact"}:
        pay_to = parameters.get("payTo")
        destination = parameters.get("destination")
        if (
            scheme != normalized_scheme
            or not _is_finite_number(value["amount"], positive=True)
            or not _is_supported_x402_network(value.get("network"))
            or not _is_nonempty_text(
                parameters.get("payTo") or parameters.get("destination")
            )
            or (
                pay_to is not None
                and destination is not None
                and pay_to != destination
            )
        ):
            _raise_malformed_payment_challenge()
    elif normalized_scheme == "payment":
        if legacy_unmapped_shape:
            return value
        if scheme != "Payment":
            _raise_malformed_payment_challenge()
        method = parameters.get("method")
        invoice = parameters.get("invoice")
        if method is not None and not _is_nonempty_text(method):
            _raise_malformed_payment_challenge()
        normalized_method = method.casefold() if type(method) is str else ""
        supported_methods = {
            "lightning",
            "mpp",
            "l402",
            "eip3009",
            "exact",
            "evm",
            "x402",
            "batch-settlement",
            "auth-capture",
        }
        if normalized_method and normalized_method not in supported_methods:
            _raise_malformed_payment_challenge()
        if invoice is not None and (
            normalized_method
            and normalized_method not in {"lightning", "mpp", "l402"}
        ):
            _raise_malformed_payment_challenge()
        if normalized_method in {"lightning", "mpp", "l402"} or invoice is not None:
            if (
                not _is_finite_number(value["amount"], positive=True)
                or value["asset"] != "SATS"
                or not _is_nonempty_text(invoice)
            ):
                _raise_malformed_payment_challenge()
        elif not normalized_method:
            _raise_malformed_payment_challenge()
        elif normalized_method in {
            "eip3009",
            "exact",
            "evm",
            "x402",
            "batch-settlement",
            "auth-capture",
        }:
            if (
                not _is_finite_number(value["amount"], positive=True)
                or not _is_supported_x402_network(value.get("network"))
                or not _is_nonempty_text(
                    parameters.get("payTo") or parameters.get("destination")
                )
            ):
                _raise_malformed_payment_challenge()
    else:
        # Body challenge markers have a closed grammar.  An unknown scheme is
        # not an inspectable extension point because marker presence alone
        # must never manufacture a settlement rail.
        if legacy_unmapped_shape:
            return value
        _raise_malformed_payment_challenge()
    return value


def _validate_accepts_payload(payload: Dict[str, Any]) -> None:
    """Reject marker-only and structurally invalid x402 accepts contracts."""
    accepts = payload.get("accepts")
    if type(accepts) is not list or not accepts:
        _raise_malformed_payment_challenge()

    for option in accepts:
        if type(option) is not dict or not option:
            _raise_malformed_payment_challenge()
        scheme = option.get("scheme")
        network = option.get("network")
        if (
            not _is_nonempty_text(scheme)
            or scheme not in _SUPPORTED_ACCEPTS_SCHEMES
            or not _is_nonempty_text(network)
            or network != network.strip()
        ):
            _raise_malformed_payment_challenge()
        if scheme != "x402" and not _is_supported_x402_network(network):
            _raise_malformed_payment_challenge()
        if not _scheme_matches_network(scheme, network):
            _raise_malformed_payment_challenge()

        for amount_field in ("amount", "maxAmountRequired"):
            if (
                amount_field in option
                and _canonical_positive_integer_string(
                    option[amount_field]
                ) is None
            ):
                _raise_malformed_payment_challenge()
        for text_field in ("asset", "symbol", "token", "mint", "payTo"):
            if text_field in option and not _is_nonempty_text(
                option[text_field]
            ):
                _raise_malformed_payment_challenge()
        if "destination" in option and not _is_nonempty_text(
            option["destination"]
        ):
            _raise_malformed_payment_challenge()
        if (
            "amount" in option
            and "maxAmountRequired" in option
            and option["amount"] != option["maxAmountRequired"]
        ):
            _raise_malformed_payment_challenge()
        if (
            "payTo" in option
            and "destination" in option
            and option["payTo"] != option["destination"]
        ):
            _raise_malformed_payment_challenge()
        asset = option.get("asset")
        symbol = option.get("symbol")
        if (
            _is_nonempty_text(asset)
            and _is_nonempty_text(symbol)
            and not (asset.startswith("0x") or len(asset) > 30)
            and asset.casefold() != symbol.casefold()
        ):
            _raise_malformed_payment_challenge()
        token_aliases = [
            option[field]
            for field in ("token", "mint")
            if field in option
        ]
        if len(token_aliases) > 1 and any(
            token != token_aliases[0] for token in token_aliases[1:]
        ):
            _raise_malformed_payment_challenge()
        if (
            token_aliases
            and _is_nonempty_text(asset)
            and (asset.startswith("0x") or len(asset) > 30)
            and any(token != asset for token in token_aliases)
        ):
            _raise_malformed_payment_challenge()
        if "decimals" in option:
            decimals = option["decimals"]
            if (
                isinstance(decimals, bool)
                or type(decimals) is not int
                or not 0 <= decimals <= 255
            ):
                _raise_malformed_payment_challenge()
        for mapping_field in ("parameters", "extra"):
            if (
                mapping_field in option
                and type(option[mapping_field]) is not dict
            ):
                _raise_malformed_payment_challenge()

    if "parameters" in payload and type(payload["parameters"]) is not dict:
        _raise_malformed_payment_challenge()

    for text_field in (
        "network",
        "asset",
        "destination",
        "payTo",
        "token_address",
        "contract",
    ):
        if text_field in payload and not _is_nonempty_text(payload[text_field]):
            _raise_malformed_payment_challenge()
    if (
        "destination" in payload
        and "payTo" in payload
        and payload["destination"] != payload["payTo"]
    ):
        _raise_malformed_payment_challenge()
    if "amount" in payload and not _is_finite_number(
        payload["amount"], positive=True
    ):
        _raise_malformed_payment_challenge()
    if "decimals" in payload:
        decimals = payload["decimals"]
        if (
            isinstance(decimals, bool)
            or type(decimals) is not int
            or not 0 <= decimals <= 255
        ):
            _raise_malformed_payment_challenge()
    for mapping_field in ("resource", "extensions"):
        if mapping_field in payload and type(payload[mapping_field]) is not dict:
            _raise_malformed_payment_challenge()
    if "x402Version" in payload:
        version = payload["x402Version"]
        if (
            isinstance(version, bool)
            or type(version) is not int
            or version not in {1, 2}
        ):
            _raise_malformed_payment_challenge()
    for chain_field in ("chainId", "chain_id"):
        if chain_field in payload:
            chain_value = payload[chain_field]
            if isinstance(chain_value, bool) or not (
                (type(chain_value) is int and chain_value > 0)
                or (
                    type(chain_value) is str
                    and re.fullmatch(r"[1-9][0-9]*", chain_value)
                )
            ):
                _raise_malformed_payment_challenge()
    if "chainId" in payload and "chain_id" in payload:
        if str(payload["chainId"]) != str(payload["chain_id"]):
            _raise_malformed_payment_challenge()
    if "network" in payload and (
        "chainId" in payload or "chain_id" in payload
    ):
        network = payload["network"]
        chain_value = payload.get("chainId", payload.get("chain_id"))
        normalized_network = _normalize_network(network)
        if (
            not normalized_network.startswith("eip155:")
            or normalized_network.split(":", 1)[1] != str(chain_value)
        ):
            _raise_malformed_payment_challenge()
    if (
        "contract" in payload
        and "token_address" in payload
        and payload["contract"] != payload["token_address"]
    ):
        _raise_malformed_payment_challenge()
    if "paymentRequirements" in payload:
        # accepts[] is the supported settlement envelope.  A second outer
        # settlement declaration is ambiguous and must not be ignored.
        _raise_malformed_payment_challenge()
    if "scheme" in payload:
        outer_scheme = payload["scheme"]
        if (
            not _is_nonempty_text(outer_scheme)
            or outer_scheme not in _SUPPORTED_ACCEPTS_SCHEMES
            or not any(option["scheme"] == outer_scheme for option in accepts)
        ):
            _raise_malformed_payment_challenge()


def _is_complete_x402_accept(option: Dict[str, Any]) -> bool:
    """Return whether an x402 alternative has the full Inspect contract."""
    return option["scheme"] != "x402" or not (
        not _is_supported_x402_network(option["network"])
        or _canonical_positive_integer_string(option.get("amount")) is None
        or not _is_nonempty_text(option.get("asset"))
        or not _is_nonempty_text(option.get("payTo"))
        or option["asset"] != option["asset"].strip()
        or option["payTo"] != option["payTo"].strip()
    )


def _validate_selected_accept(option: Dict[str, Any]) -> None:
    """Require a selected executable x402 option to carry a full contract."""
    if not _is_complete_x402_accept(option):
        _raise_malformed_payment_challenge()


def _accept_asset_candidates(option: Dict[str, Any]) -> set:
    option_network = _normalize_network(option["network"])
    candidates = {
        value
        for value in (option.get("asset"), option.get("symbol"))
        if _is_nonempty_text(value)
    }
    option_asset = option.get("asset")
    if _is_nonempty_text(option_asset) and (
        option_asset.startswith("0x") or len(option_asset) > 30
    ):
        lookup_asset = (
            option_asset
            if option_network.startswith("solana:")
            else option_asset.lower()
        )
        known_meta = TRUSTED_TOKENS.get(f"{option_network}_{lookup_asset}")
        if known_meta:
            candidates.add(known_meta["asset"])
    return candidates


def _accept_token_candidates(option: Dict[str, Any]) -> set:
    return {
        value
        for value in (
            option.get("token"),
            option.get("mint"),
            option.get("asset"),
        )
        if _is_nonempty_text(value)
        and (value.startswith("0x") or len(value) > 30)
    }


def _accept_projection_matches(
    option: Dict[str, Any],
    projection: Dict[str, Any],
    *,
    allow_supplement: bool,
) -> bool:
    """Compare only security-relevant aliases; ignore extension metadata."""
    if type(projection) is not dict:
        return False

    if "scheme" in projection and projection["scheme"] != option["scheme"]:
        return False

    option_network = _normalize_network(option["network"])
    if "network" in projection:
        network = projection["network"]
        if not _is_nonempty_text(network) or _normalize_network(network) != option_network:
            return False

    chain_values = []
    for chain_field in ("chainId", "chain_id"):
        if chain_field not in projection:
            continue
        chain_value = projection[chain_field]
        if isinstance(chain_value, bool) or not (
            (type(chain_value) is int and chain_value > 0)
            or (
                type(chain_value) is str
                and re.fullmatch(r"[1-9][0-9]*", chain_value)
            )
        ):
            return False
        chain_values.append(str(chain_value))
    if chain_values:
        if (
            any(value != chain_values[0] for value in chain_values[1:])
            or not option_network.startswith("eip155:")
            or option_network.split(":", 1)[1] != chain_values[0]
        ):
            return False

    if "asset" in projection:
        asset = projection["asset"]
        candidates = _accept_asset_candidates(option)
        if not _is_nonempty_text(asset) or (
            candidates and asset not in candidates
        ) or (not candidates and not allow_supplement):
            return False

    projection_tokens = [
        projection[field]
        for field in ("contract", "token_address", "token", "mint")
        if field in projection
    ]
    if projection_tokens:
        if any(not _is_nonempty_text(value) for value in projection_tokens):
            return False
        candidates = _accept_token_candidates(option)
        if not candidates or any(value not in candidates for value in projection_tokens):
            return False

    if "decimals" in projection:
        decimals = projection["decimals"]
        if (
            isinstance(decimals, bool)
            or type(decimals) is not int
            or not 0 <= decimals <= 255
        ):
            return False
        option_decimals = option.get("decimals")
        if option_decimals is not None and decimals != option_decimals:
            return False
        if option_decimals is None and not allow_supplement:
            return False

    atomic_amount = _canonical_positive_integer_string(option.get("amount"))
    accepted_amounts = set()
    if atomic_amount is not None:
        accepted_amounts.add(Decimal(atomic_amount))
        decimals = option.get("decimals", projection.get("decimals", 6))
        if type(decimals) is int and 0 <= decimals <= 255:
            accepted_amounts.add(
                Decimal(atomic_amount) / (Decimal(10) ** decimals)
            )
    for amount_field in ("amount", "maxAmountRequired"):
        if amount_field not in projection:
            continue
        amount = projection[amount_field]
        if not _is_finite_number(amount, positive=True):
            return False
        if accepted_amounts:
            if Decimal(str(amount)) not in accepted_amounts:
                return False
        elif not allow_supplement:
            return False

    projected_pay_values = [
        projection[field]
        for field in ("payTo", "destination")
        if field in projection
    ]
    if projected_pay_values:
        if any(not _is_nonempty_text(value) for value in projected_pay_values):
            return False
        if any(
            value != projected_pay_values[0]
            for value in projected_pay_values[1:]
        ):
            return False
        selected_pay_to = option.get("payTo") or option.get("destination")
        if selected_pay_to is not None:
            if projected_pay_values[0] != selected_pay_to:
                return False
        elif not allow_supplement:
            return False
    return True


def _inspect_payment_payload_semantically_valid(payload: Dict[str, Any]) -> bool:
    """Validate Inspect-only minima without breaking legacy parser callers."""
    if "accepts" in payload:
        # Historical parser consumers inspect sparse, unselected x402 options.
        # Keep that direct-parser view, but never publish any option or rail
        # from it through Inspect.
        return all(
            _is_complete_x402_accept(option)
            and _accept_projection_matches(
                option,
                option.get("parameters", {}),
                allow_supplement=False,
            )
            and _accept_projection_matches(
                option,
                option.get("extra", {}),
                allow_supplement=False,
            )
            for option in payload["accepts"]
        )
    scheme = payload.get("scheme")
    return scheme in _SUPPORTED_DIRECT_PAYMENT_SCHEMES


def _validate_explicit_payment_payload(payload: Dict[str, Any]) -> None:
    """Validate a non-accepts JSON challenge with an explicit scheme."""
    for field in ("scheme", "network", "asset"):
        if not _is_nonempty_text(payload.get(field)):
            _raise_malformed_payment_challenge()
    if payload["asset"] != payload["asset"].strip():
        _raise_malformed_payment_challenge()
    if "amount" not in payload or not _is_finite_number(
        payload["amount"], positive=True
    ):
        _raise_malformed_payment_challenge()
    scheme = payload["scheme"].strip().casefold()
    if scheme in {"l402", "mpp", "payment"}:
        # These rails have dedicated WWW/body grammars.  Generic JSON must not
        # manufacture them without their authentication contract.
        _raise_malformed_payment_challenge()
    if scheme not in _SUPPORTED_DIRECT_PAYMENT_SCHEMES:
        # Preserve the one deployed parser-extension fixture.  Inspect marks
        # it semantically invalid before classification; arbitrary unknown
        # schemes do not receive this compatibility exception.
        if payload["scheme"] == "CustomL2Scheme":
            return
        _raise_malformed_payment_challenge()
    if payload["scheme"] != scheme:
        _raise_malformed_payment_challenge()
    if (
        not _is_supported_x402_network(payload["network"])
        or not _scheme_matches_network(scheme, payload["network"])
    ):
        _raise_malformed_payment_challenge()
    pay_values = [
        payload[field]
        for field in ("destination", "payTo")
        if field in payload
    ]
    if (
        not pay_values
        or any(
            not _is_nonempty_text(value) or value != value.strip()
            for value in pay_values
        )
    ):
        _raise_malformed_payment_challenge()
    if (
        "destination" in payload
        and "payTo" in payload
        and payload["destination"] != payload["payTo"]
    ):
        _raise_malformed_payment_challenge()
    if "maxAmountRequired" in payload:
        if (
            _canonical_positive_integer_string(payload["maxAmountRequired"])
            is None
            or Decimal(str(payload["amount"]))
            != Decimal(str(payload["maxAmountRequired"]))
        ):
            _raise_malformed_payment_challenge()
    if "parameters" in payload and type(payload["parameters"]) is not dict:
        _raise_malformed_payment_challenge()

    for chain_field in ("chainId", "chain_id"):
        if chain_field in payload:
            chain_value = payload[chain_field]
            if isinstance(chain_value, bool) or not (
                (type(chain_value) is int and chain_value > 0)
                or (
                    type(chain_value) is str
                    and re.fullmatch(r"[1-9][0-9]*", chain_value)
                )
            ):
                _raise_malformed_payment_challenge()
    if "chainId" in payload and "chain_id" in payload:
        if str(payload["chainId"]) != str(payload["chain_id"]):
            _raise_malformed_payment_challenge()
    if "chainId" in payload or "chain_id" in payload:
        chain_value = str(payload.get("chainId", payload.get("chain_id")))
        normalized_network = _normalize_network(payload["network"])
        if (
            not normalized_network.startswith("eip155:")
            or normalized_network.split(":", 1)[1] != chain_value
        ):
            _raise_malformed_payment_challenge()

    if "decimals" in payload:
        decimals = payload["decimals"]
        if (
            isinstance(decimals, bool)
            or type(decimals) is not int
            or not 0 <= decimals <= 255
        ):
            _raise_malformed_payment_challenge()
    if "symbol" in payload:
        symbol = payload["symbol"]
        if not _is_nonempty_text(symbol) or symbol != symbol.strip():
            _raise_malformed_payment_challenge()
        asset = payload["asset"]
        asset_is_identifier = asset.startswith("0x") or len(asset) > 30
        if not asset_is_identifier and symbol.casefold() != asset.casefold():
            _raise_malformed_payment_challenge()

    token_values = [
        payload[field]
        for field in ("contract", "token_address", "token", "mint")
        if field in payload
    ]
    if token_values:
        if (
            any(
                not _is_nonempty_text(value) or value != value.strip()
                for value in token_values
            )
            or any(value != token_values[0] for value in token_values[1:])
        ):
            _raise_malformed_payment_challenge()
        asset = payload["asset"]
        if (
            (asset.startswith("0x") or len(asset) > 30)
            and token_values[0] != asset
        ):
            _raise_malformed_payment_challenge()

    parameters = payload.get("parameters", {})
    if "scheme" in parameters and parameters["scheme"] != payload["scheme"]:
        _raise_malformed_payment_challenge()
    if "network" in parameters and (
        not _is_nonempty_text(parameters["network"])
        or _normalize_network(parameters["network"])
        != _normalize_network(payload["network"])
    ):
        _raise_malformed_payment_challenge()
    for chain_field in ("chainId", "chain_id"):
        if chain_field in parameters:
            chain_value = parameters[chain_field]
            normalized_network = _normalize_network(payload["network"])
            if (
                isinstance(chain_value, bool)
                or not (
                    (type(chain_value) is int and chain_value > 0)
                    or (
                        type(chain_value) is str
                        and re.fullmatch(r"[1-9][0-9]*", chain_value)
                    )
                )
                or not normalized_network.startswith("eip155:")
                or normalized_network.split(":", 1)[1] != str(chain_value)
            ):
                _raise_malformed_payment_challenge()
    if "asset" in parameters and parameters["asset"] != payload["asset"]:
        _raise_malformed_payment_challenge()
    if "amount" in parameters and (
        not _is_finite_number(parameters["amount"], positive=True)
        or Decimal(str(parameters["amount"])) != Decimal(str(payload["amount"]))
    ):
        _raise_malformed_payment_challenge()
    if "decimals" in parameters:
        nested_decimals = parameters["decimals"]
        if (
            isinstance(nested_decimals, bool)
            or type(nested_decimals) is not int
            or not 0 <= nested_decimals <= 255
            or (
                "decimals" in payload
                and nested_decimals != payload["decimals"]
            )
        ):
            _raise_malformed_payment_challenge()
    direct_pay_to = payload.get("payTo") or payload.get("destination")
    nested_pay_values = [
        parameters[field]
        for field in ("payTo", "destination")
        if field in parameters
    ]
    if nested_pay_values and (
        any(not _is_nonempty_text(value) for value in nested_pay_values)
        or any(value != direct_pay_to for value in nested_pay_values)
    ):
        _raise_malformed_payment_challenge()
    nested_tokens = [
        parameters[field]
        for field in ("contract", "token_address", "token", "mint")
        if field in parameters
    ]
    if nested_tokens:
        direct_tokens = {
            value
            for value in (
                payload.get("contract"),
                payload.get("token_address"),
                payload.get("token"),
                payload.get("mint"),
                payload.get("asset"),
            )
            if _is_nonempty_text(value)
            and (value.startswith("0x") or len(value) > 30)
        }
        if (
            any(not _is_nonempty_text(value) for value in nested_tokens)
            or not direct_tokens
            or any(value not in direct_tokens for value in nested_tokens)
        ):
            _raise_malformed_payment_challenge()


def _validate_payment_payload(payload: Any) -> Dict[str, Any]:
    """Recognize only one of the two supported JSON challenge envelopes."""
    if type(payload) is not dict or not payload:
        _raise_malformed_payment_challenge()
    if any(
        marker in payload
        for marker in ("payment", "settlement", "accepted_payments", "schema_version")
    ):
        _raise_malformed_payment_challenge()
    if "challenge" in payload and not _is_nonempty_text(payload["challenge"]):
        _raise_malformed_payment_challenge()
    if "accepts" in payload:
        _validate_accepts_payload(payload)
    elif "scheme" in payload:
        _validate_explicit_payment_payload(payload)
    else:
        # x402Version, paymentRequirements, resource, or another marker alone
        # is not a payment contract and must not synthesize a default scheme.
        _raise_malformed_payment_challenge()
    return payload


def _selected_accept_matches_outer(
    payload: Dict[str, Any], option: Dict[str, Any]
) -> bool:
    """Reject contradictory outer aliases before Inspect publishes selection."""
    return _accept_projection_matches(
        option,
        payload,
        allow_supplement=True,
    ) and _accept_projection_matches(
        option,
        payload.get("parameters", {}),
        allow_supplement=False,
    )


def _validate_canonical_paid_surface_siblings(
    body: Dict[str, Any], headers: Any
) -> None:
    """Keep canonical paid-surface validation from masking peer markers."""
    if any(
        marker in body
        for marker in (
            "challenge",
            "accepts",
            "x402Version",
            "paymentRequirements",
            "resource",
            "extensions",
            "payment",
            "settlement",
        )
    ):
        _raise_malformed_payment_challenge()

    normalized_header_names = {
        str(name).casefold() for name, _value in headers.items()
    }
    # The frozen canonical contract intentionally carries PAYMENT-REQUIRED
    # plus x-402-payment-required, both checked against the canonical body by
    # _parse_paid_surface_challenge.  The third legacy alias is never part of
    # that split-view contract.
    if "x-payment-required" in normalized_header_names:
        _raise_malformed_payment_challenge()

    if "surface" in body:
        surface = body["surface"]
        if type(surface) is not dict:
            _raise_malformed_payment_challenge()
        if "payment_intent" in surface and not _is_nonempty_text(
            surface["payment_intent"]
        ):
            _raise_malformed_payment_challenge()


def _validate_okx_body_payment_marker(body: Dict[str, Any]) -> None:
    """Validate an OKX payment sibling before a challenge can mask it."""
    marker_fields = [
        field for field in ("payment", "settlement") if field in body
    ]
    if not marker_fields:
        return
    if len(marker_fields) != 1 or str(body.get("protocol", "")).casefold() not in {
        "okx-app",
        "okx_app",
    }:
        _raise_malformed_payment_challenge()
    marker = body[marker_fields[0]]
    if type(marker) is not dict or not marker:
        _raise_malformed_payment_challenge()
    method = marker.get("method")
    network = marker.get("network")
    asset = marker.get("asset")
    if (
        not _is_nonempty_text(method)
        or method.casefold() != "eip3009"
        or not _is_nonempty_text(network)
        or network.casefold()
        not in {"196", "eip155:196", "xlayer", "x-layer"}
        or not _is_nonempty_text(asset)
        or asset.upper() != "USDG"
    ):
        _raise_malformed_payment_challenge()
    if "amount" in marker and not _is_finite_number(
        marker["amount"], positive=True
    ):
        _raise_malformed_payment_challenge()


def _validate_response_body_payment_markers(body: Any) -> None:
    """Validate every body marker even when a header has parser priority."""
    if type(body) is not dict:
        return
    _validate_okx_body_payment_marker(body)
    if "challenge" in body:
        if any(
            marker in body
            for marker in (
                "accepts",
                "accepted_payments",
                "paymentRequirements",
                "x402Version",
                "payment",
                "settlement",
            )
        ):
            _raise_malformed_payment_challenge()
        for mapping_field in ("resource", "extensions"):
            if mapping_field in body and type(body[mapping_field]) is not dict:
                _raise_malformed_payment_challenge()
        _validate_body_challenge_marker(body["challenge"])
        return
    if any(
        marker in body
        for marker in (
            "accepts",
            "accepted_payments",
            "x402Version",
            "paymentRequirements",
            "resource",
        )
    ):
        _validate_payment_payload(body)


def _parse_supported_www_authenticate(header_val: str) -> ParsedChallenge:
    """Parse WWW auth and retain an Inspect-only semantic-validity signal."""
    parts = header_val.strip().split(None, 1)
    scheme = parts[0] if parts else ""
    raw_params = parts[1] if len(parts) == 2 else ""
    params, valid = _parse_http_auth_params(raw_params)
    semantically_valid = bool(valid and params)

    if scheme == "L402":
        required = (params.get("macaroon"), params.get("invoice"))
        semantically_valid = semantically_valid and all(
            _is_nonempty_text(value) for value in required
        )
    elif scheme in {"MPP", "Payment"}:
        request_present = "request" in params
        request_json: Dict[str, Any] = {}
        method_details: Dict[str, Any] = {}
        if request_present:
            request_json, request_valid, request_duplicate = (
                _decode_mpp_request(params["request"])
            )
            semantically_valid = (
                semantically_valid
                and request_valid
                and bool(request_json)
                and not request_duplicate
            )
            details_present, details_value, details_unique = (
                _casefold_json_field(request_json, "methodDetails")
            )
            if not details_unique or (
                details_present and not isinstance(details_value, dict)
            ):
                semantically_valid = False
            elif details_present:
                method_details = details_value

        method_present, method_value, method_consistent, _ = (
            _resolve_mpp_control_field(
                params, request_json, method_details, "method"
            )
        )
        intent_present, intent_value, intent_consistent, _ = (
            _resolve_mpp_control_field(
                params, request_json, method_details, "intent"
            )
        )
        allowed_methods = (
            {"lightning"}
            if scheme == "MPP"
            else {
                "lightning",
                "eip3009",
                "exact",
                "evm",
                "x402",
                "batch-settlement",
                "auth-capture",
            }
        )
        semantically_valid = (
            semantically_valid
            and method_consistent
            and intent_consistent
            and (
                not method_present
                or method_value in allowed_methods
            )
            and (
                not intent_present
                or intent_value in {"charge", "session"}
            )
        )

        invoice_present, invoice_value, invoice_consistent = _resolve_mpp_field(
            params, request_json, method_details, "invoice"
        )
        currency_present, currency_value, currency_consistent = _resolve_mpp_field(
            params, request_json, method_details, "currency"
        )
        amount_present, amount_value, amount_consistent = _resolve_mpp_field(
            params, request_json, method_details, "amount"
        )
        lightning_amount_semantics = scheme == "MPP" or (
            method_present and method_value == "lightning"
        ) or not method_present
        semantically_valid = (
            semantically_valid
            and currency_consistent
            and amount_consistent
            and (
                not currency_present
                or _normalize_mpp_currency(currency_value) is not None
            )
            and (
                not amount_present
                or (
                    _canonical_mpp_amount_decimal(amount_value) is not None
                    if lightning_amount_semantics
                    else _is_finite_number(amount_value, positive=True)
                )
            )
        )
        needs_invoice = scheme == "MPP" or (
            method_present and method_value == "lightning"
        ) or not method_present
        if needs_invoice:
            semantically_valid = (
                semantically_valid
                and invoice_consistent
                and invoice_present
                and _is_nonempty_text(invoice_value)
            )
        elif not request_present:
            semantically_valid = False
        elif scheme == "Payment":
            # Only the deployed eip3009 Payment draft has a defined
            # non-Lightning minimum.  A method/intent marker without a
            # positive amount must not publish Payment/x402 rails.
            semantically_valid = (
                semantically_valid
                and method_present
                and method_value == "eip3009"
                and amount_consistent
                and amount_present
                and _is_finite_number(amount_value, positive=True)
            )
    elif scheme == "x402":
        semantically_valid = semantically_valid and (
            _is_nonempty_text(params.get("macaroon"))
            and (
                _is_nonempty_text(params.get("invoice"))
                or _is_nonempty_text(params.get("txhash"))
            )
        )
    else:
        semantically_valid = False

    parsed = parse_www_authenticate(
        header_val,
        source=ChallengeSource.STANDARD_WWW,
    )
    parsed._inspect_semantically_valid = semantically_valid
    return parsed


def _parse_supported_flat_payment_header(
    header_val: str,
    *,
    source: ChallengeSource,
) -> ParsedChallenge:
    """Parse the supported legacy x402 grammar without implicit defaults."""
    if not _is_nonempty_text(header_val):
        _raise_malformed_payment_challenge()
    params, valid = _parse_http_auth_params(header_val)
    if not valid or not params:
        _raise_malformed_payment_challenge()

    field_projection = {
        "scheme": "scheme",
        "network": "network",
        "amount": "amount",
        "maxamountrequired": "maxAmountRequired",
        "asset": "asset",
        "symbol": "symbol",
        "token": "token",
        "mint": "mint",
        "contract": "contract",
        "token_address": "token_address",
        "decimals": "decimals",
        "destination": "destination",
        "payto": "payTo",
        "chainid": "chainId",
        "chain_id": "chain_id",
    }
    for key in params:
        if key in {"parameters", "extra"}:
            _raise_malformed_payment_challenge()
        if "." in key:
            nested_parts = key.split(".")
            if (
                nested_parts[0] in {"parameters", "extra"}
                and any(part in field_projection for part in nested_parts[1:])
            ):
                _raise_malformed_payment_challenge()

    projection = {
        projected: params[key]
        for key, projected in field_projection.items()
        if key in params
    }
    if "decimals" in projection:
        raw_decimals = projection["decimals"]
        if (
            len(raw_decimals) > 3
            or re.fullmatch(r"0|[1-9][0-9]*", raw_decimals) is None
        ):
            _raise_malformed_payment_challenge()
        projection["decimals"] = int(raw_decimals)

    _validate_explicit_payment_payload(projection)
    scheme = projection["scheme"]
    if scheme not in _SUPPORTED_FLAT_X402_SCHEMES:
        _raise_malformed_payment_challenge()
    network = projection["network"]
    amount = projection["amount"]
    asset = projection["asset"]

    canonical_params = dict(params)
    if "payto" in canonical_params:
        canonical_params["payTo"] = canonical_params["payto"]
    parsed = ParsedChallenge(
        scheme=scheme,
        network=network,
        amount=float(Decimal(amount)),
        asset=asset,
        parameters=canonical_params,
        source=source,
        raw_header=header_val,
    )
    parsed._inspect_semantically_valid = True
    return parsed

def b64url_decode_json(b64_str: str) -> dict:
    try:
        decoded_bytes = _strict_b64url_decode(b64_str)

        def reject_duplicate_keys(pairs):
            decoded_object = {}
            seen = set()
            for key, value in pairs:
                normalized = key.casefold()
                if normalized in seen:
                    raise ValueError("duplicate JSON key")
                seen.add(normalized)
                decoded_object[key] = value
            return decoded_object

        decoded = json.loads(
            decoded_bytes.decode('utf-8'),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
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
    return _parse_supported_flat_payment_header(
        header_val,
        source=ChallengeSource.LEGACY_CUSTOM,
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
        converted = float(val)
        return converted if math.isfinite(converted) else 0.0
    except (OverflowError, ValueError, TypeError):
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
        known_display_assets = {
            "lightning:sats": "SATS",
            "ln-church:faucet-credit": "FAUCET_CREDIT",
            "ln-church:grant-credit": "GRANT_CREDIT",
        }
        expected_asset = known_display_assets.get(
            requirement["asset_identifier"],
            requirement["asset_identifier"],
        )
        if displayed_asset != expected_asset:
            mismatches.append("asset")
    if "amount" in option:
        raw_amount = option["amount"]
        if isinstance(raw_amount, bool) or isinstance(raw_amount, float):
            mismatches.append("amount")
        else:
            try:
                display_amount = Decimal(str(raw_amount))
                if (
                    not display_amount.is_finite()
                    or display_amount != _canonical_display_amount(requirement)
                ):
                    mismatches.append("amount")
            except (InvalidOperation, ValueError):
                mismatches.append("amount")
    if mismatches:
        raise PaymentContractError(
            "Paid-surface display fields contradict canonical requirement: "
            + ", ".join(sorted(set(mismatches)))
        )


def _validate_nonpayment_canonical_requirement(
    requirement: Dict[str, Any],
) -> None:
    """Validate the two frozen non-payment alternatives in the v1 contract."""
    expected_fields = {
        "faucet": {
            "authorization_scheme": "Faucet",
            "asset_identifier": "ln-church:faucet-credit",
            "chain": "none",
            "network": "none",
            "decimals": 0,
        },
        "none": {
            "authorization_scheme": "Grant",
            "asset_identifier": "ln-church:grant-credit",
            "chain": "none",
            "network": "none",
            "decimals": 0,
        },
    }
    expected = expected_fields.get(requirement["rail"])
    if expected is None or any(
        requirement[field] != value for field, value in expected.items()
    ):
        raise PaymentContractError(
            "Canonical non-payment alternative has inconsistent fields."
        )
    if requirement["pay_to"] != requirement["origin"]:
        raise PaymentContractError(
            "Canonical non-payment alternative pay_to is inconsistent."
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

    canonical_seen = False
    incomplete_seen = False
    for option in options:
        if type(option) is not dict or not option:
            raise PaymentChallengeError(
                "Fail-Closed: malformed canonical paid-surface option."
            )
        if option.get("canonical_requirement") is None:
            incomplete_seen = True
        else:
            canonical_seen = True

    if not canonical_seen:
        # Preserve direct-parser compatibility for the deployed legacy view,
        # but never allow marker-only fields to prove Inspect validity.
        first = options[0]
        parsed = ParsedChallenge(
            scheme=str(first.get("settlement_rail", "unknown")),
            network="unknown",
            amount=_safe_float(first.get("amount", 0)),
            asset=str(first.get("asset", "unknown")),
            parameters={"_selection_reason": "missing_canonical_requirement"},
            source=ChallengeSource.BODY_CHALLENGE,
            draft_shape="ln_church.paid_surface_challenge.v1-inspect-only",
        )
        parsed._inspect_semantically_valid = False
        return parsed
    if incomplete_seen:
        raise PaymentChallengeError(
            "Fail-Closed: incomplete canonical paid-surface option."
        )

    selected_l402 = None
    for option in options:
        raw_requirement = option["canonical_requirement"]
        credential = option.get("credential_challenge")
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
            _validate_paid_surface_display_fields(option, requirement)

            if requirement["rail"] in {"faucet", "none"}:
                _validate_nonpayment_canonical_requirement(requirement)
                if "credential_challenge" in option:
                    raise PaymentContractError(
                        "Non-payment canonical alternative has a credential challenge."
                    )
                continue
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
            if "WWW-Authenticate" in response.headers:
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
            if payment_required is not None:
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

            if (
                normalized_allowed is not None
                and requirement["network"].lower() not in normalized_allowed
            ):
                continue

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
                    body.get("surface", {}).get("payment_intent", "charge")
                ),
            )
            parsed._invoice_msats = int(requirement["amount_atomic"])
            parsed._atomic_amount = requirement["amount_atomic"]
            parsed._canonical_requirement = requirement
            parsed._inspect_semantically_valid = True
            if selected_l402 is None:
                selected_l402 = parsed
        except (PaymentContractError, ValueError, TypeError):
            raise PaymentChallengeError(
                "Fail-Closed: malformed canonical paid-surface option."
            ) from None

    if selected_l402 is not None:
        return selected_l402
    raise PaymentChallengeError(
        "Fail-Closed: no executable canonical paid-surface option."
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
        _validate_canonical_paid_surface_siblings(body, h)
        return _parse_paid_surface_challenge(
            response,
            body,
            allowed_networks=allowed_networks,
            now=int(time.time()) if now is None else now,
            logical_request_url=request_url,
            logical_request_method=request_method,
            logical_idempotency_key=request_idempotency_key,
        )

    _validate_response_body_payment_markers(body)

    auth_h = h.get("WWW-Authenticate", "")
    payment_headers = []
    for header_name, header_value in h.items():
        normalized_name = str(header_name).casefold()
        if normalized_name in {
            "payment-required",
            "x-payment-required",
            "x-402-payment-required",
        }:
            payment_headers.append((normalized_name, header_value))

    auth_schemes = _www_authenticate_schemes(auth_h) if auth_h else ()
    payment_auth_schemes = {
        scheme
        for scheme in auth_schemes
        if scheme in _SUPPORTED_PAYMENT_AUTH_SCHEMES
    }
    unsupported_auth_schemes = {
        scheme
        for scheme in auth_schemes
        if scheme not in _SUPPORTED_PAYMENT_AUTH_SCHEMES
        and scheme not in _NON_PAYMENT_AUTH_SCHEMES
    }
    if auth_h and (not auth_schemes or unsupported_auth_schemes):
        _raise_malformed_payment_challenge()

    body_has_payment_marker = type(body) is dict and any(
        marker in body
        for marker in (
            "challenge",
            "accepts",
            "accepted_payments",
            "x402Version",
            "paymentRequirements",
            "resource",
            "payment",
            "settlement",
        )
    )
    leading_auth_scheme = auth_h.strip().split(None, 1)[0].casefold() if auth_h.strip() else ""
    legacy_l402_body_view = (
        not payment_headers
        and leading_auth_scheme == "l402"
        and type(body) is dict
        and type(body.get("challenge")) is dict
        and body["challenge"].get("scheme") == "L402"
    )
    identical_header_body_view = False
    if (
        len(payment_headers) == 1
        and not payment_auth_schemes
        and type(body) is dict
        and payment_headers[0][0] != "x-402-payment-required"
    ):
        identical_header_body_view = (
            b64url_decode_json(payment_headers[0][1]) == body
        )
    if (
        body_has_payment_marker
        and (payment_headers or payment_auth_schemes)
        and not legacy_l402_body_view
        and not identical_header_body_view
    ):
        # Generic paid surfaces have no canonical cross-source binding.  Even
        # two individually valid declarations are ambiguous and cannot be
        # resolved by source precedence.  The canonical P0-2 shape is handled
        # by its dedicated validator above.
        _raise_malformed_payment_challenge()

    if payment_auth_schemes and leading_auth_scheme not in _SUPPORTED_PAYMENT_AUTH_SCHEMES:
        # A supported-looking payment challenge hidden behind another WWW
        # scheme still has to validate; it cannot be ignored by precedence.
        _raise_malformed_payment_challenge()
    unbound_x402_fallback_view = False
    if payment_headers and payment_auth_schemes:
        l402_legacy_priority = (
            leading_auth_scheme == "l402"
            and len(payment_headers) == 1
            and payment_headers[0][0] == "payment-required"
        )
        validated_x402_fallback = False
        if leading_auth_scheme == "x402":
            parsed_x402_fallback = _parse_supported_www_authenticate(auth_h)
            validated_x402_fallback = getattr(
                parsed_x402_fallback,
                "_inspect_semantically_valid",
                False,
            )
            unbound_x402_fallback_view = validated_x402_fallback
        if not l402_legacy_priority and not validated_x402_fallback:
            _raise_malformed_payment_challenge()

    if auth_h.upper().startswith(("L402", "PAYMENT", "MPP")):
        parsed_auth = _parse_supported_www_authenticate(auth_h)
        if legacy_l402_body_view:
            # Preserve direct parser/client compatibility for the historic
            # trust-evaluator fixture, but do not let Inspect publish an
            # unbound cross-source amount/asset view as a valid rail.
            parsed_auth._inspect_semantically_valid = False
        return parsed_auth

    if not payment_headers and auth_h.upper().startswith("X402"):
        return _parse_supported_www_authenticate(auth_h)

    if len(payment_headers) > 1:
        # Distinct payment-header aliases are ambiguous.  Never choose the
        # first and silently ignore a conflicting malformed declaration.
        _raise_malformed_payment_challenge()

    payload = None
    source_type = ChallengeSource.STANDARD_X402
    raw_header_val = payment_headers[0][1] if payment_headers else None

    if payment_headers:
        header_name, pay_req = payment_headers[0]
        if header_name == "x-402-payment-required":
            return _parse_supported_flat_payment_header(
                pay_req,
                source=ChallengeSource.LEGACY_CUSTOM,
            )
        payload = b64url_decode_json(pay_req)
        if not payload:
            return _parse_supported_flat_payment_header(
                pay_req,
                source=source_type,
            )

    if payload is None and isinstance(body, dict):
        if "challenge" in body:
            if any(
                marker in body
                for marker in (
                    "accepts",
                    "paymentRequirements",
                    "x402Version",
                )
            ):
                _raise_malformed_payment_challenge()
            for mapping_field in ("resource", "extensions"):
                if (
                    mapping_field in body
                    and type(body[mapping_field]) is not dict
                ):
                    _raise_malformed_payment_challenge()
            c = _validate_body_challenge_marker(body["challenge"])
            parsed_body = ParsedChallenge(
                scheme=c["scheme"],
                network=c.get("network", "unknown"),
                amount=_safe_float(c["amount"]),
                asset=c["asset"],
                parameters=c.get("parameters", {}),
                source=ChallengeSource.BODY_CHALLENGE
            )
            parsed_body._inspect_semantically_valid = True
            return parsed_body
        if any(
            key in body
            for key in (
                "accepts",
                "x402Version",
                "paymentRequirements",
                "resource",
            )
        ):
            payload = body
            source_type = ChallengeSource.BODY_CHALLENGE
            raw_header_val = None

    if payload:
        payload = _validate_payment_payload(payload)
        inspect_semantically_valid = _inspect_payment_payload_semantically_valid(
            payload
        )
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
                _validate_selected_accept(selected_accept)
                if not _selected_accept_matches_outer(payload, selected_accept):
                    inspect_semantically_valid = False
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

                if selected_accept["scheme"] == "exact":
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
                        scheme=selected_accept["scheme"],
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
                    "scheme": selected_accept["scheme"],
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
                # Retain the first explicit requirement's public policy
                # metadata without selecting it.  This keeps the caller's
                # allowed-network rejection ahead of amount execution while
                # never synthesizing a fallback scheme or selected option.
                first = all_accepted[0]
                first_atomic = _canonical_positive_integer_string(
                    first.get("amount")
                )
                first_asset = first.get("asset", expected_asset)
                first_network = _normalize_network(first["network"])
                first_token = (
                    first_asset
                    if isinstance(first_asset, str)
                    and (first_asset.startswith("0x") or len(first_asset) > 30)
                    else ""
                )
                lookup_token = (
                    first_token
                    if first_network.startswith("solana:")
                    else first_token.lower()
                )
                known_meta = TRUSTED_TOKENS.get(
                    f"{first_network}_{lookup_token}"
                )
                first_decimals = first.get("decimals")
                if type(first_decimals) is not int:
                    first_decimals = (
                        known_meta["decimals"] if known_meta else 6
                    )
                first_logical_asset = (
                    first.get("symbol")
                    or payload.get("asset")
                    or (known_meta["asset"] if known_meta else expected_asset)
                )
                if first_atomic is not None:
                    first_human_dec = Decimal(first_atomic) / Decimal(
                        10 ** first_decimals
                    )
                    accepted_params.update({
                        "scheme": first["scheme"],
                        "network": first_network,
                        "amount": float(first_human_dec),
                        "atomic_amount": first_atomic,
                        "asset": first_logical_asset,
                        "payTo": first.get("payTo", ""),
                        "token_address": first_token,
                        "decimals": first_decimals,
                    })
                    canonical_req = _UnselectedPolicyAmountView(
                        network=first_network,
                        decimals=first_decimals,
                        atomic_amount=first_atomic,
                        human_amount_decimal=first_human_dec,
                    )

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

        parsed_scheme = accepted_params.get("scheme") or payload.get("scheme")
        if parsed_scheme is None and "accepts" in payload:
            parsed_scheme = payload["accepts"][0]["scheme"]
        pc = ParsedChallenge(
            scheme=parsed_scheme,
            network=params["network"],
            amount=_safe_float(params["amount"]),
            asset=params["asset"],
            parameters=params,
            source=source_type,
            raw_header=raw_header_val
        )
        pc._inspect_semantically_valid = not (
            not inspect_semantically_valid
            or unbound_x402_fallback_view
            or accepted_params.get("_selection_reason")
            == "outer_inner_mismatch"
        )
        if canonical_req is not None:
            pc._atomic_amount = canonical_req.atomic_amount
            pc._canonical_requirement = canonical_req
        return pc

    raise NoValidPaymentChallengeError(
        "No valid 402 challenge found in headers or body."
    )
