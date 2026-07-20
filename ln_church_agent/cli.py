import argparse
import requests
import httpx
import re
import os
import json
from enum import Enum
from decimal import Decimal, InvalidOperation
from typing import Optional, List, Tuple
from .models import InspectResult, SettlementOption, ObservatoryMetadata
from .challenges import parse_challenge_from_response
from .exceptions import NoValidPaymentChallengeError, PaymentChallengeError
from .app_inspect import detect_commerce_surface, detect_app_surface, build_commerce_guidance
from .grant_signals import detect_grant_signals
from .models import GrantSignalObservation
from .inspect_transport import InspectTransportError, _inspect_request
from .redaction import _contains_inspect_secret_material, redact_inspect_public_url


class _ChallengeParserOutcome(Enum):
    """Fixed internal outcome; attacker-controlled exception text is excluded."""

    NOT_APPLICABLE = "not_applicable"
    PARSED = "parsed"
    NO_VALID_CHALLENGE = "no_valid_challenge"
    PARSE_FAILURE = "parse_failure"
    UNEXPECTED_ERROR = "unexpected_error"


_PAYMENT_CHALLENGE_HEADERS = frozenset({
    "payment-required",
    "x-payment-required",
    "x-402-payment-required",
})
_NON_PAYMENT_AUTH_SCHEMES = frozenset({
    "basic",
    "bearer",
    "digest",
    "negotiate",
})
_SETTLEMENT_BODY_MARKERS = frozenset({
    "challenge",
    "accepts",
    "accepted_payments",
    "x402Version",
    "paymentRequirements",
    "resource",
})

def _requests_to_httpx_response(req_res: requests.Response, method: str = "GET") -> httpx.Response:
    # Body access is part of the response adapter boundary.  If it fails, let
    # the caller report ``response_adapter`` rather than silently parsing an
    # invented empty body.
    content = req_res.content or b""

    unsafe_headers = {
        "content-encoding",
        "transfer-encoding",
        "content-length",
    }

    safe_headers = {
        k: v
        for k, v in req_res.headers.items()
        if k.lower() not in unsafe_headers
    }

    return httpx.Response(
        status_code=req_res.status_code,
        headers=safe_headers,
        content=content,
        request=httpx.Request(method.upper(), req_res.url)
    )

def _settlement_rail_from_scheme(scheme: str, parsed=None) -> Optional[str]:
    if type(scheme) is not str or not scheme or scheme.lower() == "unknown":
        return "unknown"
    if scheme in ["exact", "batch-settlement", "auth-capture"]:
        return "x402"
    if scheme == "Payment" and parsed:
        raw_method = getattr(parsed, "payment_method", None)
        method = raw_method.lower() if type(raw_method) is str else ""
        parameters = getattr(parsed, "parameters", {})
        parameters = parameters if type(parameters) is dict else {}
        if method == "lightning" or parameters.get("invoice"):
            return "MPP"
        if method in ["eip3009", "exact", "evm", "x402", "batch-settlement", "auth-capture"]:
            return "x402"
        return "unknown"
    if scheme in ["L402", "MPP", "Payment", "x402"]:
        return scheme
    return "unknown"

CHAIN_HINTS = {
    "1": "Ethereum",
    "137": "Polygon",
    "8453": "Base",
    "196": "X Layer",
    "11155111": "Ethereum Sepolia"
}

_PUBLIC_SCHEMES = frozenset(
    {"exact", "batch-settlement", "auth-capture", "L402", "MPP", "Payment", "x402"}
)
_PUBLIC_INTENTS = frozenset(
    {
        "charge", "session", "batch", "escrow", "upto", "payment_mandate",
        "checkout_mandate", "mandate", "agentic_checkout", "cart", "catalog",
        "delegated_payment", "unknown",
    }
)
_PUBLIC_NETWORKS = frozenset({
    "unknown", "lightning", "btc",
    "eip155:1", "eip155:137", "eip155:196", "eip155:8453",
    "eip155:11155111",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
})
_PUBLIC_ASSET_SYMBOLS = frozenset({
    "BTC", "ETH", "JPYC", "SAT", "SATS", "USDC", "USDG", "unknown",
})
_PUBLIC_EVM_ASSET_ADDRESSES = frozenset({
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29",
})
_PUBLIC_SVM_ASSET_ADDRESSES = frozenset({
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
})
_LIGHTNING_INVOICE_RE = re.compile(r"^(?:lnbc|lntb|lnbcrt)[0-9a-z]{20,}$", re.IGNORECASE)
_JWT_LIKE_RE = re.compile(
    r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
)
_HEX_PRIVATE_KEY_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_LONG_BASE58_SECRET_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{45,128}$")
_PUBLIC_SELECTION_REASONS = frozenset(
    {
        "unknown", "not_selected", "no_allowed_network_match",
        "expected_chain_id", "prefer_svm", "first_acceptable",
        "fallback_first_presented", "invalid_network",
        "outer_inner_mismatch", "invalid_atomic_amount",
        "unknown_token_contract", "single_option_provided",
        "canonical_paid_surface_v1", "missing_canonical_requirement",
        "locally_bound_known_lightning", "locally_bound_known_exact",
    }
)


def _contains_public_control(value: str) -> bool:
    return any(
        ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F
        for char in value
    )


def _looks_like_secret_material(value: str) -> bool:
    normalized = value.strip()
    lowered = normalized.lower()
    return (
        _contains_public_control(normalized)
        or _contains_inspect_secret_material(normalized)
        or _LIGHTNING_INVOICE_RE.fullmatch(normalized) is not None
        or _JWT_LIKE_RE.fullmatch(normalized) is not None
        or _HEX_PRIVATE_KEY_RE.fullmatch(normalized) is not None
        or _LONG_BASE58_SECRET_RE.fullmatch(normalized) is not None
        or "private key" in lowered
        or "macaroon" in lowered
        or "preimage" in lowered
        or "credential" in lowered
        or "signature" in lowered
        or "receipt_token" in lowered
        or "access_token" in lowered
        or "refresh_token" in lowered
        or re.search(r"\bsecret\b", lowered) is not None
        or lowered.startswith(("bearer ", "basic "))
        or "-----begin" in lowered
    )


def _public_scheme(value: any) -> str:
    if type(value) is str and value in _PUBLIC_SCHEMES:
        return value
    return "REDACTED"


def _public_network(value: any) -> Optional[str]:
    if not isinstance(value, str) or _looks_like_secret_material(value):
        return "REDACTED" if value is not None else None
    normalized = value.lower()
    if normalized in {"unknown", "lightning", "btc"}:
        return normalized
    return value if value in _PUBLIC_NETWORKS else "REDACTED"


def _public_asset(value: any) -> Optional[str]:
    if not isinstance(value, str) or _looks_like_secret_material(value):
        return "REDACTED" if value is not None else None
    if value in _PUBLIC_ASSET_SYMBOLS:
        return value
    if value.lower() in _PUBLIC_EVM_ASSET_ADDRESSES:
        return value.lower()
    if value in _PUBLIC_SVM_ASSET_ADDRESSES:
        return value
    return "REDACTED"


def _public_amount(value: any) -> Optional[str]:
    if value is None:
        return None
    candidate = str(value)
    if len(candidate) > 128 or _looks_like_secret_material(candidate):
        return "REDACTED"
    # Amounts are attacker-controlled scalar strings and can encode arbitrary
    # identifiers even when they are syntactically numeric.  Inspect reports
    # only the existence of an amount, not its raw value.
    return "REDACTED"


def _public_intent(value: any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return "unknown"
    normalized = value.lower()
    return normalized if normalized in _PUBLIC_INTENTS else "unknown"


def _public_x402_pay_to(value: any, network: any) -> Optional[str]:
    del network
    if value is None:
        return None
    # Recipient addresses are caller-controlled scalar identifiers.  They are
    # never needed for Inspect classification or observation reporting.
    return "REDACTED"


def _public_settlement_method(value: any) -> Optional[str]:
    if value is None:
        return None
    return (
        value
        if type(value) is str and value in {"evm_eip3009", "unknown"}
        else "REDACTED"
    )


def _public_selection_reason(value: any) -> str:
    return (
        value
        if type(value) is str and value in _PUBLIC_SELECTION_REASONS
        else "unknown"
    )

def _determine_chain_info(network: str) -> Tuple[str, Optional[str]]:
    if not network or network.lower() == "unknown":
        return "unknown", None
    n_lower = network.lower()
    if n_lower.startswith("eip155:"):
        chain_id = n_lower.split(":")[1]
        hint = CHAIN_HINTS.get(chain_id)
        return "evm", hint
    if n_lower.startswith("solana:"):
        return "svm", "Solana"
    if n_lower in ["lightning", "btc"]:
        return "lightning", "Lightning Network"
    return "unknown", None

def _extract_settlement_options(parsed: Optional[any]) -> Tuple[List[SettlementOption], Optional[SettlementOption]]:
    if not parsed:
        return [], None

    options = []
    selected_option = None
    parameters = getattr(parsed, "parameters", {})
    parameters = parameters if type(parameters) is dict else {}
    raw_accepted = parameters.get("_raw_accepted")
    raw_accepted = raw_accepted if type(raw_accepted) is dict else None
    all_accepted = parameters.get("_all_accepted", [])
    all_accepted = all_accepted if type(all_accepted) is list else []
    reason_from_parser = _public_selection_reason(
        parameters.get("_selection_reason", "unknown")
    )

    if not all_accepted and parsed.scheme in ["L402", "MPP", "Payment"]:
        public_network = _public_network(parsed.network)
        cf, ch = _determine_chain_info(public_network or "unknown")
        rail = _settlement_rail_from_scheme(parsed.scheme, parsed) or parsed.scheme
        raw_pay_to = parameters.get("destination") or parameters.get("invoice")
        public_pay_to = (
            "REDACTED"
            if rail in {"L402", "MPP"}
            else _public_x402_pay_to(raw_pay_to, public_network)
        )
        opt = SettlementOption(
            rail=rail,
            scheme=_public_scheme(parsed.scheme),
            network=public_network,
            chain_family=cf,
            chain_name_hint=ch,
            asset=_public_asset(parsed.asset),
            amount=_public_amount(parsed.amount),
            pay_to=public_pay_to,
            source="www_authenticate",
            execution_support="supported_but_not_executed_in_inspect" if rail in ["L402", "MPP"] else "unknown",
            selected=True,
            selection_reason="single_option_provided"
        )
        return [opt], opt

    # The challenge body is untrusted. Bound work and ignore malformed entries
    # instead of letting a mixed-type ``accepts`` array escape as an exception.
    for idx, req in enumerate(all_accepted[:32]):
        if type(req) is not dict:
            continue
        net = _public_network(req.get("network", "unknown")) or "unknown"
        cf, ch = _determine_chain_info(net)
        sch = _public_scheme(req.get("scheme", "exact"))
        
        support = "unknown"
        settlement_model = None
        authorization_artifact = None
        finality_model = None
        requires_channel_state = None
        deferred_settlement = None

        if sch == "exact": 
            support = "observe_only"
        elif sch == "batch-settlement":
            support = "observe_only"
            settlement_model = "deferred_batch"
            authorization_artifact = "voucher"
            finality_model = "deferred_onchain"
            requires_channel_state = True
            deferred_settlement = True
        elif sch == "auth-capture":
            support = "observe_only"
            settlement_model = "auth_capture_deferred_refundable"
            authorization_artifact = "authorization_signature"
            finality_model = "capture_void_refund_reclaim_lifecycle"
            requires_channel_state = False
            deferred_settlement = True
        elif cf in ["evm", "svm", "lightning"]: 
            support = "supported_but_not_executed_in_inspect"
        else: 
            support = "unsupported"
            
        is_selected = False
        reason = "not_selected"
        
        if raw_accepted and req == raw_accepted:
            is_selected = True
            reason = reason_from_parser
        elif reason_from_parser == "no_allowed_network_match":
            reason = "no_allowed_network_match"

        raw_amt = _public_amount(
            req.get("amount") or req.get("maxAmountRequired")
        )
        asset_val = _public_asset(
            req.get("symbol") or req.get("asset") or req.get("token") or req.get("mint")
        )
        
        opt = SettlementOption(
            rail="x402",
            scheme=sch,
            network=net,
            chain_family=cf,
            chain_name_hint=ch,
            asset=asset_val,
            amount=raw_amt,
            amount_atomic=raw_amt,
            pay_to=_public_x402_pay_to(req.get("payTo"), net),
            source=f"accepts[{idx}]",
            # A requirement-derived digest is still an attacker-controlled
            # scalar and can be used as a dictionary-testable covert channel.
            # Inspect exposes only this fixed representation.
            raw_requirement_fingerprint="REDACTED",
            execution_support=support,
            selected=is_selected,
            selection_reason=reason,
            settlement_model=settlement_model,
            authorization_artifact=authorization_artifact,
            finality_model=finality_model,
            requires_channel_state=requires_channel_state,
            deferred_settlement=deferred_settlement
        )
        options.append(opt)
        if is_selected:
            selected_option = opt
        
    return options, selected_option


def _www_authenticate_schemes(value: str) -> Tuple[str, ...]:
    """Return auth challenge schemes without reading quoted auth params."""
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
        schemes.append(match.group(1).lower())
    return tuple(schemes)


def _has_payment_or_settlement_marker(
    response: httpx.Response,
    commerce_info,
) -> bool:
    """Detect marker presence only when the parser reported true absence.

    A successfully parsed challenge remains governed by the existing parser.
    This predicate prevents an ignored or malformed marker from borrowing a
    successful AP2/ACP/OKX commerce classification.
    """
    headers = {
        str(name).lower(): str(value)
        for name, value in response.headers.items()
    }
    if any(name in headers for name in _PAYMENT_CHALLENGE_HEADERS):
        return True

    auth_value = headers.get("www-authenticate")
    if auth_value is not None:
        auth_schemes = _www_authenticate_schemes(auth_value)
        if not auth_schemes:
            return True
        if any(
            scheme not in _NON_PAYMENT_AUTH_SCHEMES
            for scheme in auth_schemes
        ):
            return True

    try:
        payload = response.json()
    except Exception:
        return False
    if type(payload) is not dict:
        return False
    if any(field in payload for field in _SETTLEMENT_BODY_MARKERS):
        return True
    marker_fields = [
        field for field in ("payment", "settlement") if field in payload
    ]
    if marker_fields:
        if (
            len(marker_fields) != 1
            or type(commerce_info) is not dict
            or commerce_info.get("commerce_protocol") != "okx_app"
        ):
            return True
        marker = payload[marker_fields[0]]
        if type(marker) is not dict or not marker:
            return True
        method = marker.get("method")
        network = marker.get("network")
        asset = marker.get("asset")
        if (
            type(method) is not str
            or method.lower() != "eip3009"
            or type(network) is not str
            or network.lower() not in {
                "196", "eip155:196", "xlayer", "x-layer",
            }
            or type(asset) is not str
            or asset.upper() != "USDG"
        ):
            return True
        if "amount" in marker:
            amount = marker["amount"]
            if isinstance(amount, bool) or not isinstance(
                amount, (str, int, float)
            ):
                return True
            amount_text = str(amount)
            if len(amount_text) > 128:
                return True
            try:
                decimal_amount = Decimal(amount_text)
            except (InvalidOperation, ValueError):
                return True
            if not decimal_amount.is_finite() or decimal_amount <= 0:
                return True
    return False


def _parse_failure_result(
    *,
    outcome: _ChallengeParserOutcome,
    public_url: str,
    status_code: int,
    grant_signals: Optional[GrantSignalObservation] = None,
) -> InspectResult:
    """Build one fixed, redacted parser result from an internal outcome."""
    if outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE:
        failure_class = "no_valid_challenge"
        diagnostic_class = "unsupported_challenge_shape"
        ok = True
        recommended_action = "reject_invalid"
    elif outcome is _ChallengeParserOutcome.PARSE_FAILURE:
        failure_class = "parse_failure"
        diagnostic_class = "invalid_payment_auth_request"
        ok = True
        recommended_action = "reject_invalid"
    else:
        failure_class = "unexpected_error"
        diagnostic_class = "x402_parse_error"
        ok = False
        recommended_action = "stop_safely"

    public_grant_signals = grant_signals or GrantSignalObservation()
    return InspectResult(
        ok=ok,
        url=public_url,
        http_status=status_code,
        error_stage="parse",
        failure_reason=failure_class,
        diagnostic_class=diagnostic_class,
        failure_class=failure_class,
        recommended_action=recommended_action,
        reason="Failed to parse challenge safely.",
        will_execute_payment=False,
        ln_church_observatory=ObservatoryMetadata(),
        grant_signal_detected=public_grant_signals.detected,
        grant_signals=public_grant_signals,
    )

def inspect_url(url: str, method: str = "GET", timeout: int = 10) -> InspectResult:
    try:
        res = _inspect_request(url, method=method, timeout=timeout)
    except InspectTransportError as exc:
        return InspectResult(
            ok=False,
            # Transport state, including redirect destinations, never defines
            # the public target identity.  Recompute it from the caller's
            # initial URL even if an internal exception carries another URL.
            url=redact_inspect_public_url(url),
            error_stage=exc.stage,
            failure_class=exc.code,
            failure_reason=exc.code,
            recommended_action="stop_safely",
            reason="Inspect request rejected by the fixed safety policy.",
            will_execute_payment=False
        )
    except Exception:
        return InspectResult(
            ok=False,
            url=redact_inspect_public_url(url),
            error_stage="transport",
            failure_class="network_error",
            failure_reason="network_error",
            recommended_action="stop_safely",
            reason="Inspect transport failed safely.",
            will_execute_payment=False,
        )

    # The public identity is always the canonical origin of the caller's
    # initial target.  A redirect destination is transport-only state: a
    # peer-controlled final authority must never replace the requested target
    # in CLI, MCP, or Observation output.
    public_url = redact_inspect_public_url(url)

    try:
        httpx_res = _requests_to_httpx_response(res, method)
    except Exception:
        challenge_status_observed = res.status_code in (401, 402, 403)
        return InspectResult(
            ok=challenge_status_observed,
            url=public_url,
            http_status=res.status_code,
            error_stage="response_adapter",
            failure_class="requests_to_httpx_conversion_failed",
            diagnostic_class="response_decoding_error",
            failure_reason="response_adapter_failed",
            recommended_action="stop_safely",
            reason="Failed to adapt the HTTP response safely.",
            will_execute_payment=False
        )

    parsed = None
    parser_outcome = _ChallengeParserOutcome.NOT_APPLICABLE
    if res.status_code in (402, 401, 403):
        try:
            parsed = parse_challenge_from_response(httpx_res)
            if getattr(parsed, "_inspect_semantically_valid", None) is not True:
                raise PaymentChallengeError("Malformed payment challenge.")
            parser_outcome = _ChallengeParserOutcome.PARSED
        except NoValidPaymentChallengeError:
            parser_outcome = _ChallengeParserOutcome.NO_VALID_CHALLENGE
        except PaymentChallengeError:
            parser_outcome = _ChallengeParserOutcome.PARSE_FAILURE
        except Exception:
            parser_outcome = _ChallengeParserOutcome.UNEXPECTED_ERROR

        if (
            parser_outcome is _ChallengeParserOutcome.PARSED
            and parsed is None
        ):
            parser_outcome = _ChallengeParserOutcome.UNEXPECTED_ERROR

        if parser_outcome in {
            _ChallengeParserOutcome.PARSE_FAILURE,
            _ChallengeParserOutcome.UNEXPECTED_ERROR,
        }:
            return _parse_failure_result(
                outcome=parser_outcome,
                public_url=public_url,
                status_code=res.status_code,
            )

    settlement_opts = []
    selected_opt = None
    try:
        if parsed:
            settlement_opts, selected_opt = _extract_settlement_options(parsed)
        commerce_info = detect_commerce_surface(httpx_res)
    except Exception:
        return InspectResult(
            ok=res.status_code in (401, 402, 403),
            url=public_url,
            http_status=res.status_code,
            error_stage="parse",
            failure_class="classification_failure",
            failure_reason="classification_failure",
            diagnostic_class="unsupported_challenge_shape",
            recommended_action="stop_safely",
            reason="Failed to classify the response safely.",
            will_execute_payment=False,
        )

    if (
        parser_outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE
        and _has_payment_or_settlement_marker(httpx_res, commerce_info)
    ):
        return _parse_failure_result(
            outcome=_ChallengeParserOutcome.PARSE_FAILURE,
            public_url=public_url,
            status_code=res.status_code,
        )

    try:
        grant_signals = detect_grant_signals(httpx_res)
    except Exception:
        grant_signals = GrantSignalObservation()

    if commerce_info:
        c_protocol = commerce_info.get("commerce_protocol")
        c_intent = _public_intent(commerce_info.get("commerce_intent"))
        
        scheme = _public_scheme(
            getattr(parsed, "scheme", "unknown") if parsed else "unknown"
        )
        if scheme == "REDACTED":
            scheme = "unknown"
        s_rail = _settlement_rail_from_scheme(scheme, parsed)
        
        surfaces_detected = []
        settlement_rails_detected = []
        rails_detected = [] 

        if c_protocol == "ap2": surfaces_detected.append("AP2")
        elif c_protocol == "acp": surfaces_detected.append("ACP")
        elif c_protocol == "okx_app":
            surfaces_detected.append("OKX_APP")
            rails_detected.append("APP")

        if scheme == "Payment":
            rails_detected.append("Payment") 
            if s_rail and s_rail not in ["Payment", "unknown"]:
                settlement_rails_detected.append(s_rail)
                rails_detected.append(s_rail)
        elif s_rail and s_rail != "unknown":
            settlement_rails_detected.append(s_rail)
            rails_detected.append(s_rail)

        action = "observe_only"
        unsupported_reason = None
        operator_approval_reason = None
        
        has_payment_headers = any(h.lower() in ["www-authenticate", "payment-required", "x-payment-required", "x-402-payment-required"] for h in httpx_res.headers.keys())
        is_malformed_hint = False
        
        if parsed and has_payment_headers and scheme == "unknown":
            is_malformed_hint = True
        elif scheme != "unknown" and s_rail not in ["x402", "L402", "MPP", "Payment"]:
            is_malformed_hint = True

        if is_malformed_hint:
            action = "stop_safely"
            unsupported_reason = "Malformed or unsupported settlement hint co-existing with commerce surface."
            operator_approval_reason = "malformed_or_unsupported_settlement_hint"
            reason = "Agent Commerce surface detected, but co-existing settlement hint is malformed or unsupported."
        elif not selected_opt and settlement_opts and parsed and parsed.parameters.get("_selection_reason") == "no_allowed_network_match":
            action = "stop_safely"
            unsupported_reason = "Settlement options are available, but none match the local allowed_networks policy."
            operator_approval_reason = "allowed_network_mismatch"
            reason = unsupported_reason
        else:
            operator_approval_reason = "commerce_surface_with_settlement_rail" if settlement_rails_detected else "commerce_surface_detected"
            if c_protocol in ["ap2", "acp"]:
                action = "observe_only"
                reason = commerce_info.get("reason", "Agent Commerce surface detected.")
                if settlement_rails_detected:
                    reason += " (Concrete HTTP 402 settlement challenge also detected, but payment is not executed by default for AP2/ACP)."
            else:
                reason = "Agent Commerce surface detected."
                if c_intent in ["session", "escrow", "upto"]:
                    action = "stop_safely"
                    reason = f"High-intent commerce flow ({c_intent}) observed but not executed by default."
                else:
                    action = "observe_only"

        try:
            guidance = build_commerce_guidance(
                c_protocol,
                commerce_info.get("raw_detected_fields", {}),
            )
        except Exception:
            return InspectResult(
                ok=res.status_code in (401, 402, 403),
                url=public_url,
                http_status=res.status_code,
                error_stage="parse",
                failure_class="classification_failure",
                failure_reason="classification_failure",
                diagnostic_class="unsupported_challenge_shape",
                recommended_action="stop_safely",
                reason="Failed to classify the response safely.",
                will_execute_payment=False,
            )

        if not settlement_opts:
            if "missing_information" not in guidance:
                guidance["missing_information"] = []
            guidance["missing_information"].extend([
                "settlement_rail_not_declared",
                "network_not_declared",
                "asset_not_declared",
                "post_payment_artifact_unknown"
            ])
            guidance["missing_information"] = list(dict.fromkeys(guidance["missing_information"]))

        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            rails_detected=rails_detected,
            surfaces_detected=surfaces_detected,
            settlement_rails_detected=settlement_rails_detected,
            surface_type=commerce_info.get("surface_type"),
            detection_confidence=commerce_info.get("confidence"),
            detection_reason=commerce_info.get("reason"),
            unsupported_reason=unsupported_reason,
            error_stage="parse" if is_malformed_hint else None,
            failure_class=(
                "unsupported_challenge_shape"
                if is_malformed_hint else None
            ),
            failure_reason=(
                "unsupported_challenge_shape"
                if is_malformed_hint else None
            ),
            recommended_action=action,
            reason=reason,
            will_execute_payment=False,
            diagnostic_class="commerce_surface_detected",
            commerce_protocol=c_protocol,
            commerce_intent=c_intent,
            commerce_transport=commerce_info.get("commerce_transport", "http"),
            authorization_artifact=commerce_info.get("authorization_artifact"),
            settlement_rail=s_rail if s_rail != "unknown" else None,
            settlement_method=_public_settlement_method(
                commerce_info.get("settlement_method")
            ),
            network=_public_network(commerce_info.get("network")),
            broker_required=commerce_info.get("broker_required"),
            classification_confidence=commerce_info.get("confidence"),
            app_protocol=c_protocol,
            app_intent=c_intent,
            app_transport=commerce_info.get("commerce_transport", "http"),
            handoff_mode=guidance.get("handoff_mode"),
            approval_required=guidance.get("approval_required"),
            ask_site_for=guidance.get("ask_site_for", []),
            do_not=guidance.get("do_not", []),
            required_evidence=guidance.get("required_evidence", []),
            missing_information=guidance.get("missing_information", []),
            operator_approval_reason=operator_approval_reason,
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    if res.status_code < 400 and res.status_code != 402:
        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            recommended_action="no_payment_required",
            reason="No HTTP 402 payment challenge detected.",
            will_execute_payment=False,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    if res.status_code in (402, 401, 403):
        if parser_outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE:
            return _parse_failure_result(
                outcome=parser_outcome,
                public_url=public_url,
                status_code=res.status_code,
                grant_signals=grant_signals,
            )

        scheme = _public_scheme(getattr(parsed, "scheme", "unknown"))
        if scheme == "REDACTED":
            scheme = "unknown"
        s_rail = _settlement_rail_from_scheme(scheme, parsed)
        
        rails = []
        if scheme == "Payment":
            rails.append("Payment")
            if s_rail and s_rail not in ["Payment", "unknown"]:
                rails.append(s_rail)
        elif s_rail and s_rail != "unknown":
            rails.append(s_rail)
        else:
            if scheme and scheme != "unknown":
                rails.append(scheme)
        
        intent = _public_intent(getattr(parsed, "payment_intent", None))
        shape = getattr(parsed, "draft_shape", None)
        source = getattr(parsed, "source", None)

        executable_rail = (
            scheme in {"L402", "MPP", "x402"}
            or (scheme == "Payment" and s_rail in {"L402", "MPP", "x402"})
        )
        action = "pay_and_verify" if executable_rail else "stop_safely"
        reason = (
            "Payment challenge detected. Inspect-only mode does not execute payments."
            if executable_rail
            else "Unsupported payment challenge shape was rejected safely."
        )
        next_cmd = None  
        diagnostic_class = None if executable_rail else "unsupported_challenge_shape"
        failure_class = None if executable_rail else "unsupported_challenge_shape"

        if not selected_opt and settlement_opts and parsed and parsed.parameters.get("_selection_reason") == "no_allowed_network_match":
            action = "stop_safely"
            diagnostic_class = "allowed_network_mismatch"
            reason = "Settlement options are available, but none match the local allowed_networks policy."
        elif intent == "session":
            action = "stop_safely"
            reason = "MPP session execution is observed but not executed by default."
            next_cmd = None
        elif scheme == "exact":
            action = "observe_only"
            diagnostic_class = "post_settlement_proof_required"
            failure_class = None
            reason = "This endpoint exposes an x402 exact challenge but validates only post-settlement evidence. The SDK-generated unbroadcasted exact payload will be rejected unless a submitted tx hash/signature is provided."
            next_cmd = None
        elif scheme == "batch-settlement":
            action = "observe_only"
            diagnostic_class = "deferred_batch_settlement_observed"
            failure_class = None
            reason = "x402 batch-settlement challenge detected. Request-time voucher / authorization artifact is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign vouchers or deposit funds."
            next_cmd = None
        elif scheme == "auth-capture":
            action = "observe_only"
            diagnostic_class = "deferred_auth_capture_observed"
            failure_class = None
            reason = "x402 auth-capture challenge detected. Authorization signature is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign, capture, void, refund, or reclaim."
            next_cmd = None
        elif shape in ["payment-auth-draft-partial", "payment-auth-draft-invalid-request"]:
            action = "reject_invalid"
            diagnostic_class = "invalid_payment_auth_request"
            reason = "Challenge shape is incomplete or invalid."
            next_cmd = None
        elif scheme == "Payment" and s_rail == "unknown":
            action = "stop_safely"
            diagnostic_class = "unsupported_challenge_shape"
            failure_class = "unsupported_challenge_shape"
            reason = "Payment scheme detected but payment method is unknown. The challenge was rejected safely."

        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            rails_detected=rails,
            settlement_rails_detected=rails, 
            challenge_source=source.value if source else None,
            payment_intent=intent,
            draft_shape=shape,
            recommended_action=action,
            reason=reason,
            next_command=next_cmd,
            will_execute_payment=False,
            diagnostic_class=diagnostic_class,
            error_stage="parse" if failure_class else None,
            failure_class=failure_class,
            failure_reason=failure_class,
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    return InspectResult(
        ok=False,
        url=public_url,
        http_status=res.status_code,
        error_stage="parse",
        failure_class="unexpected_http_status",
        failure_reason="unexpected_http_status",
        recommended_action="stop_safely",
        reason="Unexpected HTTP status during inspection.",
        will_execute_payment=False,
        grant_signal_detected=grant_signals.detected,
        grant_signals=grant_signals
    )

def main():
    parser = argparse.ArgumentParser(description="ln-church-agent CLI - Agentic Payment Runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Existing `inspect`
    inspect_parser = subparsers.add_parser("inspect", help="Inspect an HTTP 402 endpoint without paying")
    inspect_parser.add_argument("url", type=str, help="Target URL")
    inspect_parser.add_argument("--method", type=str, default="GET", help="HTTP method (default: GET)")
    inspect_parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    inspect_parser.add_argument("--json", action="store_true", help="Output result as JSON")
    
    # 2. Existing `grant`
    grant_parser = subparsers.add_parser("grant", help="Manage and inspect grant tokens")
    grant_subparsers = grant_parser.add_subparsers(dest="grant_command", required=True)
    
    grant_inspect_parser = grant_subparsers.add_parser("inspect", help="Inspect a grant token locally without sending it")
    grant_inspect_parser.add_argument("--token", type=str, required=True, help="JWS Grant Token")
    grant_inspect_parser.add_argument("--agent-id", type=str, required=True, help="Expected Agent ID")
    grant_inspect_parser.add_argument("--route", type=str, default="/api/agent/omikuji", help="Target route")
    grant_inspect_parser.add_argument("--method", type=str, default="POST", help="Target HTTP method")
    grant_inspect_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="Target base URL")

    # 💡 3. [NEW] Paid Registration & Read Models (`observe-domain`)
    obs_domain_parser = subparsers.add_parser("observe-domain", help="Manage paid domain observation slots")
    obs_domain_sub = obs_domain_parser.add_subparsers(dest="obs_cmd", required=True)
    
    register_parser = obs_domain_sub.add_parser("register", help="Register a domain (Paid Action)")
    register_parser.add_argument("domain", type=str, help="Public domain to observe")
    register_parser.add_argument("--pay", action="store_true", help="Acknowledge this is a paid action (approx 1 USDC)")
    register_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    register_parser.add_argument("--private-key", type=str, help="Agent EVM Private Key (or set via ENV)")
    register_parser.add_argument("--idempotency-key", type=str, help="Optional idempotency key to prevent double charges")
    register_parser.add_argument("--json", action="store_true", help="Output as JSON")

    status_parser = obs_domain_sub.add_parser("status", help="Get request status")
    status_parser.add_argument("request_id", type=str, help="The Observation Request ID")
    status_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    status_parser.add_argument("--json", action="store_true")

    rm_parser = obs_domain_sub.add_parser("read-model", help="Get domain read model")
    rm_parser.add_argument("domain", type=str, help="The target domain")
    rm_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    rm_parser.add_argument("--json", action="store_true")

    # 💡 4. [NEW] Internal Observatory (default_worker) (`observatory`)
    observatory_parser = subparsers.add_parser("observatory", help="Internal Observer API")
    obs_sub = observatory_parser.add_subparsers(dest="observatory_cmd", required=True)
    
    targets_parser = obs_sub.add_parser("targets")
    targets_sub = targets_parser.add_subparsers(dest="targets_cmd", required=True)
    claim_parser = targets_sub.add_parser("claim", help="Claim targets for observation")
    claim_parser.add_argument("--observer", type=str, default="default_worker")
    claim_parser.add_argument("--limit", type=int, default=5)
    claim_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    claim_parser.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    claim_parser.add_argument("--json", action="store_true")

    results_parser = obs_sub.add_parser("results")
    results_sub = results_parser.add_subparsers(dest="results_cmd", required=True)
    submit_parser = results_sub.add_parser("submit", help="Submit observation result")
    submit_parser.add_argument("file", type=str, help="Path to result JSON file")
    submit_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    submit_parser.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    submit_parser.add_argument("--json", action="store_true")

    # 💡1.15.0
    sponsor_parser = obs_domain_sub.add_parser("sponsor", help="Manage domain sponsor verification")
    sponsor_sub = sponsor_parser.add_subparsers(dest="sponsor_cmd", required=True)
    
    chal_cmd = sponsor_sub.add_parser("challenge", help="Issue a sponsor challenge")
    chal_cmd.add_argument("request_id", type=str, help="Observation Request ID")
    chal_cmd.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    chal_cmd.add_argument("--result-handle", type=str, help="Proof handle (or LN_CHURCH_RESULT_HANDLE env)")
    chal_cmd.add_argument("--request-hash", type=str, help="Proof hash (or LN_CHURCH_REQUEST_HASH env)")
    chal_cmd.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    chal_cmd.add_argument("--json", action="store_true", help="Output JSON response (excludes headers)")
    chal_cmd.add_argument("--output-file", type=str, help="Save challenge document safely to a file")
    chal_cmd.add_argument("--print-document", action="store_true", help="Print challenge document JSON to stdout")
    chal_cmd.add_argument("--proof-file", type=str, help="Load result-handle/request-hash from proof file")

    ver_cmd = sponsor_sub.add_parser("verify", help="Verify the sponsor challenge")
    ver_cmd.add_argument("request_id", type=str, help="Observation Request ID")
    ver_cmd.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    ver_cmd.add_argument("--result-handle", type=str)
    ver_cmd.add_argument("--request-hash", type=str)
    ver_cmd.add_argument("--internal-secret", type=str)
    ver_cmd.add_argument("--json", action="store_true")
    ver_cmd.add_argument("--proof-file", type=str, help="Load result-handle/request-hash from proof file")

    track_parser = obs_domain_sub.add_parser("track", help="Manage Verified Domain Tracks")
    track_sub = track_parser.add_subparsers(dest="track_cmd", required=True)
    
    trk_reg = track_sub.add_parser("register", help="Register a Verified Domain Track (Paid Action)")
    trk_reg.add_argument("domain", type=str)
    trk_reg.add_argument("--plan", type=str, default="verified_domain_track_lite")
    trk_reg.add_argument("--idempotency-key", type=str)
    trk_reg.add_argument("--proof-file", type=str)
    trk_reg.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_reg.add_argument("--json", action="store_true")
    
    trk_reg.add_argument("--pay", action="store_true", help="Acknowledge this is a paid action (19 USDC)")
    trk_reg.add_argument("--max-spend-usd", type=float, default=25.0, help="Max spend for this transaction (default: 25.0)")
    trk_reg.add_argument("--private-key", type=str, help="Agent EVM Private Key (or AGENT_PRIVATE_KEY)")
    trk_reg.add_argument("--include-proof", action="store_true", help="Include secret proof details in JSON output")
    
    trk_stat = track_sub.add_parser("status", help="Get Verified Domain Track Status")
    trk_stat.add_argument("request_id", type=str)
    trk_stat.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_stat.add_argument("--json", action="store_true")

    trk_dom = track_sub.add_parser("domain", help="Get Domain Verified Track Read Model")
    trk_dom.add_argument("domain", type=str)
    trk_dom.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_dom.add_argument("--json", action="store_true")

    args = parser.parse_args()

    # --- CLI Execution Handlers ---

    if args.command == "inspect":
        result = inspect_url(args.url, args.method, args.timeout)
        if args.json:
            print(result.model_dump_json(exclude_none=True, indent=2))
        else:
            print(f"🔍 Inspection Result for {result.url}")
            print(f"  OK                 : {result.ok}")
            print(f"  HTTP Status        : {result.http_status}")
            print(f"  Action             : {result.recommended_action}")
            print(f"  Rails Detected     : {', '.join(result.rails_detected) if result.rails_detected else 'None'}")
            print(f"  Surfaces Detected  : {', '.join(result.surfaces_detected) if result.surfaces_detected else 'None'}")
            print(f"  Reason             : {result.reason}")
            
            if result.settlement_options:
                print(f"  Settlement Options : {len(result.settlement_options)} available")
                for i, opt in enumerate(result.settlement_options):
                    sel_mark = "*" if opt.selected else "-"
                    print(f"    {sel_mark} [{opt.chain_family}] {opt.network} - {opt.asset} (Scheme: {opt.scheme})")
                    
            if result.next_command:
                print(f"  Next Command       : {result.next_command}")
            if getattr(result, "diagnostic_class", None):
                print(f"  Diagnostic Class   : {result.diagnostic_class}")
            if not result.ok and result.failure_reason:
                print(f"  Failure            : {result.error_stage} -> {result.failure_reason}")

            if getattr(result, "grant_signal_detected", False):
                print(f"  Grant Signal       : detected (confidence: {result.grant_signals.confidence})")
                if result.grant_signals.signal_types:
                    print(f"  Grant Signal Type  : {', '.join(result.grant_signals.signal_types)}")

            print("\n---------------------------------------------------------")
            print("💡 Observation generated locally. This result was not submitted.")
            print("To contribute a redacted observation to the public corpus, use an explicit opt-in submission flow.")
            print("LN Church Observatory collects agent-readable evidence for HTTP 402 / x402 / L402 / MPP payment surfaces.")
            print("---------------------------------------------------------")

    elif args.command == "grant" and args.grant_command == "inspect":
        from .grants import diagnose_grant_token
        import json
        diag = diagnose_grant_token(args.token, agent_id=args.agent_id, base_url=args.base_url, route=args.route, method=args.method)
        res = {
            "usable": diag.usable,
            "failure_class": diag.failure_class,
            "access_path": diag.access_path,
            "authorization_artifact": diag.authorization_artifact,
            "settlement_rail": diag.settlement_rail,
            "scope": {
                "routes": diag.scope_routes,
                "methods": diag.scope_methods
            },
            "recommended_action": diag.recommended_action,
            "note": "Local diagnostics only. Server-side validation is authoritative."
        }
        if diag.reason:
            res["reason"] = diag.reason
        if diag.fallback_action:
            res["fallback_action"] = diag.fallback_action
        print(json.dumps(res, indent=2))

    # 💡 [NEW] Paid Domain Observation Slot Management
    elif args.command == "observe-domain":
        from .client import LnChurchClient
        import os, json

        def _load_proof_file(proof_file: str):
            import json
            with open(proof_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            rh = data.get("result_handle")
            rhsh = data.get("request_hash")

            if not rh or not rhsh:
                raise ValueError("Proof file is missing result_handle or request_hash.")

            return rh, rhsh

        if args.obs_cmd == "register":
            pk = getattr(args, "private_key", None) or os.environ.get("AGENT_PRIVATE_KEY")
            if not pk:
                print("❌ Error: --private-key or AGENT_PRIVATE_KEY environment variable is required to register a domain.")
                return
            if not args.pay:
                print("❌ Safety Check Failed: This is a paid endpoint. Use '--pay' to explicitly acknowledge the payment action.")
                return
                
            client = LnChurchClient(private_key=pk)
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.register_domain_observation_slot(args.domain, idempotency_key=args.idempotency_key)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Slot Registered for {res.domain}")
                    print(f"  Request ID    : {res.request_id}")
                    print(f"  Requester Paid: {res.requester_paid}")
                    print(f"  Result Handle : {res.result_handle}")
                    print(f"  Read Model    : {res.public_read_model_url}")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "status":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.get_domain_observation_request(args.request_id)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Status for {res.domain}:")
                    print(f"  Request ID : {res.request_id}")
                    print(f"  Status     : {res.status}")
                    print(f"  Observed   : {res.observation_count} times (Last: {res.last_observed_at or 'Never'})")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "read-model":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.get_domain_observation_read_model(args.domain)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Read Model for {res.domain}:")
                    print(f"  Latest Observations : {len(res.latest_observations)}")
                    print(f"  Discovered Surfaces : {len(res.discovered_surfaces)}")
                    print(f"  Verdict / Score     : None (not_a_verdict=True)")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "sponsor":
            client = LnChurchClient(agent_id="cli_sponsor")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            rh = getattr(args, "result_handle", None)
            rhsh = getattr(args, "request_hash", None)
            secret = getattr(args, "internal_secret", None) or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
            
            if hasattr(args, "proof_file") and args.proof_file and (not rh or not rhsh):
                f_rh, f_rhsh = _load_proof_file(args.proof_file)
                if not rh: rh = f_rh
                if not rhsh: rhsh = f_rhsh

            rh = rh or os.environ.get("LN_CHURCH_RESULT_HANDLE")
            rhsh = rhsh or os.environ.get("LN_CHURCH_REQUEST_HASH")

            if args.sponsor_cmd == "challenge":
                try:
                    res = client.create_domain_sponsor_challenge(
                        args.request_id, result_handle=rh, request_hash=rhsh, internal_secret=secret
                    )
                    
                    if args.output_file:
                        client.save_domain_sponsor_challenge_document(res, args.output_file)
                        if not args.json and not args.print_document:
                            print("✅ Challenge document saved.")
                            print(f"  File      : {args.output_file}")
                            print(f"  Publish   : {res.challenge_url}")
                            print(f"  Verify    : ln-church-agent observe-domain sponsor verify {res.request_id}")
                            
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    elif args.print_document:
                        print(json.dumps(res.challenge_document, indent=2, ensure_ascii=False))
                    elif not args.output_file:
                        print("✅ Domain sponsor challenge issued.")
                        print(f"  Request ID : {res.request_id}")
                        print(f"  Domain     : {res.domain}")
                        print(f"  Challenge  : {res.challenge_url}")
                        print(f"  Scope      : domain_control_not_legal_ownership\n")
                        print("Challenge document contains a public challenge_token.")
                        print("Use --output-file .well-known/ln-church-domain-sponsor.json to save it safely.")
                        
                except Exception as e:
                    print(f"❌ Failed: {e}")

            elif args.sponsor_cmd == "verify":
                try:
                    res = client.verify_domain_sponsor(
                        args.request_id, result_handle=rh, request_hash=rhsh, internal_secret=secret
                    )
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print("✅ Domain-control sponsor verified.")
                        print(f"  Request ID              : {res.request_id}")
                        print(f"  Domain                  : {res.domain}")
                        print(f"  Domain Control Verified : {res.domain_control_verified}")
                        print(f"  Scope                   : {res.verification_scope}")
                        print(f"  Legal Ownership Proof   : {res.not_legal_ownership_proof is not True}")
                        print(f"  Read Model              : {res.public_read_model_url}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

        elif args.obs_cmd == "track":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            if args.track_cmd == "register":
                # [追加] 安全確認: $19の決済エンドポイントであることの明示同意
                if not getattr(args, "pay", False):
                    import sys
                    sys.stderr.write("❌ Safety Check Failed: This is a paid endpoint. Use '--pay' to explicitly acknowledge the 19 USDC payment action.\n")
                    return

                pk = getattr(args, "private_key", None) or os.environ.get("AGENT_PRIVATE_KEY")
                if not pk:
                    print("❌ Error: AGENT_PRIVATE_KEY or --private-key is required to purchase a track.")
                    return
                
                # [追加] $19決済が弾かれないようにPaymentPolicyを上書き
                from .models import PaymentPolicy
                policy = PaymentPolicy(
                    max_spend_per_tx_usd=args.max_spend_usd,
                    max_spend_per_session_usd=args.max_spend_usd
                )
                
                client = LnChurchClient(private_key=pk, policy=policy)
                if hasattr(args, "base_url") and args.base_url:
                    client.base_url = args.base_url

                try:
                    res = client.register_verified_domain_track(
                        args.domain,
                        plan_id=args.plan,
                        idempotency_key=args.idempotency_key
                    )
                    
                    if args.proof_file:
                        client.save_verified_domain_track_proof(res, args.proof_file)

                    if args.json:
                        import json
                        exclude_fields = {"result_handle", "request_hash"} if not getattr(args, "include_proof", False) else None
                        safe_dump = res.model_dump(exclude=exclude_fields)
                        print(json.dumps(safe_dump, indent=2))
                    else:
                        print("✅ Domain-Control Verified Observation Track Lite purchased.\n")
                        print(f"Domain      : {res.domain}")
                        print(f"Request ID  : {res.request_id}")
                        print(f"Status      : {res.status}")
                        print(f"Track Plan  : {res.track_plan}")
                        if res.price:
                            print(f"Price       : {res.price.amount} {res.price.currency}")
                        if args.proof_file:
                            print(f"📄 Proof saved to: {args.proof_file}")

                except Exception as e:
                    import sys
                    if args.json:
                        sys.stderr.write(f"Error: {e}\n")
                    else:
                        print(f"❌ Track registration failed: {e}")

            elif args.track_cmd == "status":
                try:
                    res = client.get_verified_domain_track_status(args.request_id)
                    if not res:
                        print("❌ Failed: Request is not a verified domain track.")
                        return
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print(f"✅ Verified Domain Track Status for {res.request_id}:")
                        print(f"  Domain                      : {res.domain}")
                        print(f"  Track Plan                  : {res.track_plan}")
                        print(f"  Track Status                : {res.track_status}")
                        print(f"  Active Verified Track       : {res.is_active_verified_track}")
                        print(f"  Domain Control Verified     : {res.domain_control_verified}")
                        print(f"  Sponsor Verified            : {res.sponsor_verified}")
                        print(f"  Sponsor Verification Status : {res.sponsor_verification_status}")
                        print(f"  Track Activated At          : {res.track_activated_at}")
                        print(f"  Track Expires At            : {res.track_expires_at}")
                        print(f"  Last Observed At            : {res.last_observed_at}")
                        print(f"  Next Observable At          : {res.next_observable_at}")
                        print(f"  Observation Interval Hours  : {res.observation_interval_hours}")
                        print(f"  Not Legal Ownership Proof   : {res.not_legal_ownership_proof}")
                        print(f"  Not A Recommendation        : {res.not_a_recommendation}")
                        print(f"  Not A Trust Score           : {res.not_a_trust_score}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

            elif args.track_cmd == "domain":
                try:
                    res = client.get_domain_verified_track(args.domain)
                    if not res:
                        print("❌ Failed: Domain not found or error occurred.")
                        return
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print(f"✅ Verified Domain Track for {args.domain}:")
                        print(f"  Has Active Verified Track : {res.has_active_verified_domain_track}")
                        if res.current_track:
                            ct = res.current_track
                            print(f"  Request ID                : {ct.request_id}")
                            print(f"  Track Status              : {ct.track_status}")
                            print(f"  Track Plan                : {ct.track_plan}")
                            print(f"  Domain Control Verified   : {ct.domain_control_verified}")
                            print(f"  Last Observed At          : {ct.last_observed_at}")
                            print(f"  Next Observable At        : {ct.next_observable_at}")
                            print(f"  Observation Interval Hours: {ct.observation_interval_hours}")
                        print(f"  Safety Flags              : not_a_verdict={res.not_a_verdict}, not_a_recommendation={res.not_a_recommendation}, not_a_trust_score={res.not_a_trust_score}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

    # 💡 [NEW] Internal Observatory (Internal Observatory Worker Tools)
    elif args.command == "observatory":
        from .client import LnChurchClient
        import os, json
        
        client = LnChurchClient(agent_id="internal_worker")
        if hasattr(args, "base_url") and args.base_url:
            client.base_url = args.base_url
            
        secret = getattr(args, "internal_secret", None) or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
        
        if args.observatory_cmd == "targets" and args.targets_cmd == "claim":
            if not secret:
                print("❌ Error: --internal-secret or LN_CHURCH_INTERNAL_SECRET environment variable is required.")
                return
            try:
                res = client.claim_domain_observation_targets(observer=args.observer, limit=args.limit, internal_secret=secret)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Claimed {len(res.targets)} targets for observation.")
                    for t in res.targets:
                        print(f"  - {t.domain} (ID: {t.target_id})")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.observatory_cmd == "results" and args.results_cmd == "submit":
            if not secret:
                print("❌ Error: --internal-secret or LN_CHURCH_INTERNAL_SECRET environment variable is required.")
                return
            try:
                with open(args.file, "r") as f:
                    data = json.load(f)
                res = client.submit_domain_observation_result(data, internal_secret=secret)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Result Submitted Successfully")
                    print(f"  Observation ID: {res.observation_id}")
            except Exception as e:
                print(f"❌ Failed: {e}")


if __name__ == "__main__":
    main()
