import json
import ipaddress
import re
from typing import Dict, Any, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError("Install with `pip install ln-church-agent[mcp]`")

from ..cli import (
    inspect_url,
    _public_asset,
    _public_intent,
    _public_network,
    _public_scheme,
    _public_selection_reason,
    _public_x402_pay_to,
)
from ..grant_signals import STRONG_TERMS, WEAK_TERMS
from ..inspect_transport import (
    CANONICAL_OBSERVATION_ENDPOINT,
    InspectTransportError,
    _canonicalize_target,
    _require_global_address,
    _submit_observation_request,
    _validate_observation_target,
)
from ..redaction import (
    QUERY_REDACTION,
    _contains_inspect_secret_material,
    redact_inspect_public_url,
)


MAX_OBSERVATION_PAYLOAD_BYTES = 64 * 1024
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:lnbc|lntb|lnbcrt)[0-9][a-z0-9]{20,}"),
    re.compile(r"(?i)\b(?:macaroon|preimage|private[_ -]?key|payment[_ -]?signature|receipt[_ -]?token)\s*[:=]"),
    re.compile(r"(?i)\b(?:secret|credential|private_key|payment_signature|receipt_token|access_token|refresh_token)\b"),
    re.compile(r"(?i)(?:^|[^a-z0-9])(?:secret|credential|private[_ -]?key|payment[_ -]?signature|receipt[_ -]?token|access[_ -]?token|refresh[_ -]?token)(?:$|[^a-z0-9])"),
    re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$"),
    re.compile(r"^[1-9A-HJ-NP-Za-km-z]{45,128}$"),
)

_PUBLIC_RAILS = frozenset({"x402", "L402", "MPP", "Payment", "unknown"})
_PUBLIC_EXECUTION_SUPPORT = frozenset({
    "observe_only", "supported_but_not_executed_in_inspect",
    "unsupported", "unknown",
})
_PUBLIC_SETTLEMENT_MODELS = frozenset({
    "deferred_batch", "auth_capture_deferred_refundable",
})
_PUBLIC_AUTHORIZATION_ARTIFACTS = frozenset({
    "voucher", "authorization_signature",
})
_PUBLIC_FINALITY_MODELS = frozenset({
    "deferred_onchain", "capture_void_refund_reclaim_lifecycle",
})
_PUBLIC_HANDOFF_MODES = frozenset({"guided_handoff"})
_PUBLIC_OPERATOR_REASONS = frozenset({
    "malformed_or_unsupported_settlement_hint",
    "allowed_network_mismatch",
    "commerce_surface_with_settlement_rail",
    "commerce_surface_detected",
})
_PUBLIC_HANDOFF_ITEMS = frozenset({
    "quote_details", "mandate_scope", "expiration", "revocation_method",
    "settlement_rail_options", "receipt_or_proof_model", "cart_details",
    "price_breakdown", "merchant_identity", "checkout_expiration",
    "payment_token_scope", "order_receipt_model", "broker_identity",
    "escrow_terms", "settlement_method", "dispute_policy",
    "treat_mandate_as_settlement_proof",
    "execute_payment_without_operator_approval", "store_raw_mandate_payload",
    "treat_shared_payment_token_as_settlement_proof",
    "execute_checkout_without_operator_approval",
    "store_raw_shared_payment_token", "treat_broker_hint_as_settlement_proof",
    "enter_escrow_without_operator_approval",
    "store_raw_broker_or_session_token", "explicit_price", "settlement_rail",
    "receipt_model", "cart_total", "order_receipt", "quote",
    "escrow_or_dispute_terms", "settlement_rail_not_declared",
    "network_not_declared", "asset_not_declared",
    "post_payment_artifact_unknown",
})
_OBSERVATION_AGENT_ID = "optional-agent-id"
_OBSERVATION_SDK_VERSION = "1.16.4"
_PUBLIC_OBSERVATION_NETWORKS = frozenset({
    "unknown", "lightning", "btc",
    "eip155:1", "eip155:137", "eip155:196", "eip155:8453",
    "eip155:11155111",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
})
_PUBLIC_OBSERVATION_ASSET_SYMBOLS = frozenset({
    "unknown", "BTC", "ETH", "SATS", "USDC", "USDG",
})
_PUBLIC_GRANT_TERMS = frozenset(STRONG_TERMS | WEAK_TERMS)
_PUBLIC_GRANT_SIGNAL_TYPES = frozenset({
    "faucet", "trial_credit", "developer_credit", "promotional_credit",
    "coupon_or_discount", "loyalty_reward", "access_entitlement",
    "sponsored_grant", "unknown_grant_like",
})
_PUBLIC_GRANT_SOURCE_KINDS = frozenset({"body_json", "body_text", "headers"})
_GRANT_SIGNAL_REASON = (
    "Grant-like signals are observed only. Redeemability and availability "
    "are not verified."
)

# ==========================================
# 🔍 Inspect-Only MCP Server Initialization
# ==========================================
mcp = FastMCP("LN_Church_Inspect_Node")

def _contains_secret_keys(obj: Any) -> bool:
    """
    Recursively check if a dictionary contains keys that match raw secret names.
    """
    rejected_keys = {
        "authorization", "www-authenticate", "payment-signature", "payment-response",
        "macaroon", "preimage", "private_key", "grant_token", "mandate_token",
        "shared_payment_token", "access_token", "refresh_token", "secret", "api_key"
    }
    
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in rejected_keys:
                return True
            if _contains_secret_keys(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _contains_secret_keys(item):
                return True
    return False


def _contains_secret_material(obj: Any) -> bool:
    if type(obj) is dict:
        return any(_contains_secret_material(value) for value in obj.values())
    if type(obj) is list:
        return any(_contains_secret_material(value) for value in obj)
    if isinstance(obj, str):
        return (
            _contains_inspect_secret_material(obj)
            or any(
                pattern.search(obj) is not None
                for pattern in _SECRET_VALUE_PATTERNS
            )
        )
    return False


def _public_settlement_pay_to(rail: Any, value: Any) -> Any:
    if str(rail).upper() in {"L402", "MPP"}:
        return QUERY_REDACTION
    return value


def _public_grant_signal_payload(value: Any) -> Dict[str, Any]:
    """Serialize the sidecar without attacker-controlled field/key names."""

    def public_list(name: str, allowed: frozenset) -> list:
        candidate = getattr(value, name, [])
        if type(candidate) is not list:
            return []
        return sorted({
            item for item in candidate[:64]
            if type(item) is str and item in allowed
        })

    def public_bool(name: str, default: bool = False) -> bool:
        candidate = getattr(value, name, default)
        return candidate if type(candidate) is bool else default

    confidence = getattr(value, "confidence", "none")
    if confidence not in {"none", "low", "medium", "high"}:
        confidence = "none"
    transferability = getattr(value, "transferability_declared", None)
    if type(transferability) is not bool:
        transferability = None
    requires_identity = getattr(value, "requires_identity", None)
    if type(requires_identity) is not bool:
        requires_identity = None

    return {
        "detected": public_bool("detected"),
        "confidence": confidence,
        "signal_types": public_list(
            "signal_types", _PUBLIC_GRANT_SIGNAL_TYPES
        ),
        "source_kinds": public_list(
            "source_kinds", _PUBLIC_GRANT_SOURCE_KINDS
        ),
        "detected_terms": public_list("detected_terms", _PUBLIC_GRANT_TERMS),
        "detected_fields": public_list("detected_fields", _PUBLIC_GRANT_TERMS),
        "machine_readable": public_bool("machine_readable"),
        "redeemability_verified": public_bool("redeemability_verified"),
        "availability_verified": public_bool("availability_verified"),
        "redemption_endpoint_present": public_bool(
            "redemption_endpoint_present"
        ),
        "verification_endpoint_present": public_bool(
            "verification_endpoint_present"
        ),
        "eligibility_declared": public_bool("eligibility_declared"),
        "scope_declared": public_bool("scope_declared"),
        "expiration_declared": public_bool("expiration_declared"),
        "transferability_declared": transferability,
        "requires_identity": requires_identity,
        "recommended_action": "observe_only",
        "diagnostic_class": "grant_like_signal_observed",
        "not_a_recommendation": True,
        "not_a_verdict": True,
        "unassessed_is_not_failed": True,
        "reason": _GRANT_SIGNAL_REASON,
    }

@mcp.tool()
def inspect_paid_surface(url: str, method: str = "GET") -> Dict[str, Any]:
    """
    Safely inspect an unknown URL for HTTP 402 / commerce surfaces (AP2/ACP/OKX APP/L402/x402/MPP).
    Does NOT execute any payments. Does NOT require a private key or wallet.
    """
    result = inspect_url(url, method=method)
    
    # 💡 v1.9.5: Serialize Settlement Options safely for MCP output
    settlement_opts = []
    for opt in getattr(result, "settlement_options", []):
        settlement_opts.append({
            "rail": opt.rail,
            "scheme": opt.scheme,
            "network": opt.network,
            "chain_family": opt.chain_family,
            "chain_name_hint": opt.chain_name_hint,
            "asset": opt.asset,
            "amount": opt.amount,
            "pay_to": (
                _public_settlement_pay_to(opt.rail, opt.pay_to)
                if str(opt.rail).upper() in {"L402", "MPP"}
                else _public_x402_pay_to(opt.pay_to, opt.network)
            ),
            "source": opt.source,
            "execution_support": opt.execution_support,
            "selected": opt.selected,
            "selection_reason": opt.selection_reason,
            "settlement_model": getattr(opt, "settlement_model", None),
            "authorization_artifact": getattr(opt, "authorization_artifact", None),
            "finality_model": getattr(opt, "finality_model", None),
            "requires_channel_state": getattr(opt, "requires_channel_state", None),
            "deferred_settlement": getattr(opt, "deferred_settlement", None)
        })
        
    selected_opt = None
    if getattr(result, "selected_settlement_option", None):
        opt = result.selected_settlement_option
        selected_opt = {
            "rail": opt.rail,
            "scheme": opt.scheme,
            "network": opt.network,
            "chain_family": opt.chain_family,
            "asset": opt.asset,
            "amount": opt.amount,
            "execution_support": opt.execution_support,
            "selected": opt.selected,
            "selection_reason": opt.selection_reason,
            "settlement_model": getattr(opt, "settlement_model", None),
            "authorization_artifact": getattr(opt, "authorization_artifact", None),
            "finality_model": getattr(opt, "finality_model", None),
            "requires_channel_state": getattr(opt, "requires_channel_state", None),
            "deferred_settlement": getattr(opt, "deferred_settlement", None)
        }

    observatory_metadata = None
    if getattr(result, "ln_church_observatory", None):
        observatory_metadata = result.ln_church_observatory.model_dump()

    public_method = method.upper() if type(method) is str else "INVALID"
    if public_method not in {"GET", "HEAD"}:
        public_method = "INVALID"

    return {
        "schema_version": "ln_church_agent.mcp.inspect_result.v1",
        "ok": result.ok,
        "url": redact_inspect_public_url(result.url),
        "method": public_method,
        "status_code": result.http_status,
        "error_stage": result.error_stage,
        "failure_class": result.failure_class,
        "failure_reason": result.failure_reason,
        "diagnostic_class": result.diagnostic_class,
        "recommended_action": result.recommended_action,
        "surfaces_detected": result.surfaces_detected,
        "settlement_rails_detected": result.settlement_rails_detected,
        "rails_detected": result.rails_detected,
        "surface_type": result.surface_type or "unknown",
        "commerce_intent": result.commerce_intent or "unknown",
        "authorization_artifact": result.authorization_artifact or "none",
        "detection_confidence": result.detection_confidence or "unknown",
        "detection_reason": result.detection_reason or "none",
        "unsupported_reason": result.unsupported_reason,
        "will_execute_payment": False,
        # --- v1.9.1 Guided Handoff fields ---
        "handoff_mode": getattr(result, "handoff_mode", None),
        "approval_required": getattr(result, "approval_required", None),
        "operator_approval_reason": getattr(result, "operator_approval_reason", None),
        "ask_site_for": getattr(result, "ask_site_for", []),
        "do_not": getattr(result, "do_not", []),
        "required_evidence": getattr(result, "required_evidence", []),
        "missing_information": getattr(result, "missing_information", []),
        # --- v1.11.2: Grant-like Signal Sidecar) ---
        "grant_signal_detected": getattr(result, "grant_signal_detected", False),
        "grant_signals": (
            _public_grant_signal_payload(result.grant_signals)
            if getattr(result, "grant_signals", None) else None
        ),
        # --- v1.9.5 Settlement Options & Observatory Metadata ---
        "settlement_options": settlement_opts,
        "selected_settlement_option": selected_opt,
        "ln_church_observatory": observatory_metadata,
        "safety": {
            "inspect_only": True,
            "payment_performed": False,
            "requires_private_key": False,
            "secrets_redacted": True
        }
    }

@mcp.tool()
def explain_recommended_action(inspect_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Explains the recommended_action from an inspect result, guiding the AI on what to do next.
    """
    source = inspect_result if type(inspect_result) is dict else {}
    action = source.get("recommended_action", "unknown")
    if type(action) is not str or action not in {
        "pay_and_verify",
        "observe_only",
        "stop_safely",
        "reject_invalid",
        "no_payment_required",
    }:
        action = "unknown"
    meaning = "Unknown action."
    safe_next_step = "Do nothing."
    
    if action == "pay_and_verify":
        meaning = "The endpoint is a standard settlement rail (e.g., L402, x402). Payment is requested."
        safe_next_step = "Use a fully configured payment execution engine if approved. Note: THIS inspect-only MCP server does NOT execute payments."
    elif action == "observe_only":
        meaning = "The endpoint is an observable commerce surface (e.g., AP2, ACP, or x402 exact). Do not execute autonomously."
        safe_next_step = "Wait for human operator review or log the surface."
    elif action == "stop_safely":
        meaning = "The endpoint requires a high-intent flow (e.g., session) or contains a malformed/unsupported payload."
        safe_next_step = "Halt execution safely and escalate to operator."
    elif action == "reject_invalid":
        meaning = "The 402 challenge shape is completely invalid or unparseable."
        safe_next_step = "Ignore this endpoint."
    elif action == "no_payment_required":
        meaning = "No HTTP 402 or commerce surface was detected."
        safe_next_step = "Proceed as a normal web request."

    handoff_mode = _public_enum(
        source.get("handoff_mode"),
        _PUBLIC_HANDOFF_MODES,
    )
    if handoff_mode == "guided_handoff":
        safe_next_step = (
            "Do not execute payment in this MCP server. Review ask_site_for, do_not, "
            "required_evidence, and missing_information, then route to operator approval "
            "or a separate managed payment execution engine if approved."
        )
        
    return {
        "schema_version": "ln_church_agent.mcp.action_explanation.v1",
        "recommended_action": action,
        "meaning": meaning,
        "safe_next_step": safe_next_step,
        "payment_execution_available_in_this_mcp": False,
        "handoff_mode": handoff_mode,
        "approval_required": source.get("approval_required")
        if type(source.get("approval_required")) is bool else None,
        "operator_approval_reason": _public_enum(
            source.get("operator_approval_reason"),
            _PUBLIC_OPERATOR_REASONS,
        ),
        "ask_site_for": _public_handoff_list(source.get("ask_site_for", [])),
        "do_not": _public_handoff_list(source.get("do_not", [])),
        "required_evidence": _public_handoff_list(
            source.get("required_evidence", [])
        ),
        "missing_information": _public_handoff_list(
            source.get("missing_information", [])
        ),
    }

def _public_enum(
    value: Any,
    allowed: frozenset,
    default: Optional[str] = None,
) -> Optional[str]:
    if type(value) is str and value in allowed:
        return value
    return default


def _public_observation_rail(
    value: Any,
    default: Optional[str] = "unknown",
) -> Optional[str]:
    return _public_enum(value, _PUBLIC_RAILS, default)


def _public_observation_scheme(
    value: Any,
    default: Optional[str] = None,
) -> Optional[str]:
    candidate = _public_scheme(value)
    return candidate if candidate != QUERY_REDACTION else default


def _public_observation_network(
    value: Any,
    default: Optional[str] = "unknown",
) -> Optional[str]:
    candidate = _public_network(value)
    return candidate if candidate in _PUBLIC_OBSERVATION_NETWORKS else default


def _public_observation_asset(
    value: Any,
    default: Optional[str] = "unknown",
) -> Optional[str]:
    candidate = _public_asset(value)
    if candidate in _PUBLIC_OBSERVATION_ASSET_SYMBOLS:
        return candidate
    if type(candidate) is str and candidate != QUERY_REDACTION:
        return candidate
    return default


def _public_observation_intent(value: Any) -> str:
    return _public_intent(value) or "unknown"


def _public_observation_agent_id(value: Any) -> str:
    del value
    return _OBSERVATION_AGENT_ID


def _public_handoff_list(value: Any) -> list:
    if not isinstance(value, (list, tuple)):
        return []
    return [
        item for item in value[:32]
        if type(item) is str and item in _PUBLIC_HANDOFF_ITEMS
    ]


def _public_observation_target(value: Any) -> str:
    public_url = redact_inspect_public_url(value)
    if public_url == QUERY_REDACTION:
        return QUERY_REDACTION
    try:
        target = _canonicalize_target(public_url)
        if target.url != public_url:
            return QUERY_REDACTION
        try:
            literal = ipaddress.ip_address(target.host)
        except ValueError:
            pass
        else:
            _require_global_address(literal.compressed)
    except (InspectTransportError, TypeError, ValueError):
        return QUERY_REDACTION
    return public_url


@mcp.tool()
def build_mcp_observation_payload(inspect_result: Dict[str, Any], agent_id: str = "optional-agent-id") -> Dict[str, Any]:
    """Build, but never submit, the fixed keyless observation schema."""
    source = inspect_result if type(inspect_result) is dict else {}
    rails = source.get("settlement_rails_detected", [])
    rail = _public_observation_rail(
        rails[0] if isinstance(rails, list) and rails else None
    )

    selected_opt = source.get("selected_settlement_option")
    selected_opt = selected_opt if type(selected_opt) is dict else None
    raw_opts = source.get("settlement_options", [])
    opts = raw_opts if isinstance(raw_opts, list) else []

    if selected_opt:
        network = _public_observation_network(selected_opt.get("network"))
        asset = _public_observation_asset(selected_opt.get("asset"))
    elif opts and type(opts[0]) is dict:
        network = _public_observation_network(opts[0].get("network"))
        asset = _public_observation_asset(opts[0].get("asset"))
    else:
        network = _public_observation_network(source.get("network"))
        asset = "unknown"

    options_summary = []
    for raw_opt in opts[:32]:
        if type(raw_opt) is not dict:
            continue
        raw_selection_reason = raw_opt.get("selection_reason")
        options_summary.append({
            "network": _public_observation_network(raw_opt.get("network"), default=None),
            "asset": _public_observation_asset(raw_opt.get("asset"), default=None),
            "rail": _public_observation_rail(raw_opt.get("rail"), default=None),
            "scheme": _public_observation_scheme(raw_opt.get("scheme"), default=None),
            "selected": raw_opt.get("selected") if type(raw_opt.get("selected")) is bool else None,
            "execution_support": _public_enum(
                raw_opt.get("execution_support"),
                _PUBLIC_EXECUTION_SUPPORT,
            ),
            "selection_reason": (
                _public_selection_reason(raw_selection_reason)
                if raw_selection_reason is not None else None
            ),
            "settlement_model": _public_enum(
                raw_opt.get("settlement_model"),
                _PUBLIC_SETTLEMENT_MODELS,
            ),
            "authorization_artifact": _public_enum(
                raw_opt.get("authorization_artifact"),
                _PUBLIC_AUTHORIZATION_ARTIFACTS,
            ),
            "finality_model": _public_enum(
                raw_opt.get("finality_model"),
                _PUBLIC_FINALITY_MODELS,
            ),
            "deferred_settlement": raw_opt.get("deferred_settlement") if type(raw_opt.get("deferred_settlement")) is bool else None,
            "requires_channel_state": raw_opt.get("requires_channel_state") if type(raw_opt.get("requires_channel_state")) is bool else None,
        })

    method = source.get("method", "GET")
    method = method.upper() if isinstance(method, str) else "GET"
    if method not in {"GET", "HEAD"}:
        method = "GET"
    status_code = source.get("status_code", 402)
    if type(status_code) is not int or not 100 <= status_code <= 599:
        status_code = 402

    selected_summary = None
    if selected_opt:
        selected_summary = {
            "network": network,
            "asset": asset,
            "rail": _public_observation_rail(selected_opt.get("rail"), default=None),
            "scheme": _public_observation_scheme(selected_opt.get("scheme"), default=None),
        }

    # Grant-like sidecar signals, raw headers/body, payment destinations, and
    # proof material are deliberately absent from this allowlist.
    return {
        "schema_version": "mcp_observation_report.v1",
        "agentId": _public_observation_agent_id(agent_id),
        "targetUrl": _public_observation_target(
            source.get("url", QUERY_REDACTION)
        ),
        "source_channel": "mcp",
        "source_scope": "external_agent_report",
        "method": method,
        "statusCode": status_code,
        "protocol": {
            "rail": rail,
            "network": network,
            "asset": asset,
            "payment_intent": _public_observation_intent(source.get("commerce_intent")),
            "payment_method": "unknown",
            "authorization_scheme": rail,
            "draft_shape": "unknown",
            "selected_settlement_option": selected_summary,
        },
        "settlement_options_summary": options_summary,
        "evidence": {
            "evidence_class": "mcp_inspect_402",
            "verification_status": "unverified",
            "verification_method": "none",
            "proof_reference": "none",
            "provider_controlled": False,
            "payment_performed": False,
            "payment_receipt_present": False,
        },
        "handoff": {
            "handoff_mode": _public_enum(
                source.get("handoff_mode"),
                _PUBLIC_HANDOFF_MODES,
            ),
            "approval_required": source.get("approval_required") if type(source.get("approval_required")) is bool else None,
            "operator_approval_reason": _public_enum(
                source.get("operator_approval_reason"),
                _PUBLIC_OPERATOR_REASONS,
            ),
            "ask_site_for": _public_handoff_list(source.get("ask_site_for", [])),
            "do_not": _public_handoff_list(source.get("do_not", [])),
            "required_evidence": _public_handoff_list(source.get("required_evidence", [])),
            "missing_information": _public_handoff_list(source.get("missing_information", [])),
        },
        "sdk_version": _OBSERVATION_SDK_VERSION,
    }

_OBSERVATION_TOP_LEVEL_KEYS = frozenset({
    "schema_version", "agentId", "targetUrl", "source_channel",
    "source_scope", "method", "statusCode", "protocol",
    "settlement_options_summary", "evidence", "handoff", "sdk_version",
})
_OBSERVATION_PROTOCOL_KEYS = frozenset({
    "rail", "network", "asset", "payment_intent", "payment_method",
    "authorization_scheme", "draft_shape", "selected_settlement_option",
})
_OBSERVATION_SELECTED_KEYS = frozenset({"network", "asset", "rail", "scheme"})
_OBSERVATION_SUMMARY_KEYS = frozenset({
    "network", "asset", "rail", "scheme", "selected",
    "execution_support", "selection_reason", "settlement_model",
    "authorization_artifact", "finality_model", "deferred_settlement",
    "requires_channel_state",
})
_OBSERVATION_EVIDENCE_KEYS = frozenset({
    "evidence_class", "verification_status", "verification_method",
    "proof_reference", "provider_controlled", "payment_performed",
    "payment_receipt_present",
})
_OBSERVATION_HANDOFF_KEYS = frozenset({
    "handoff_mode", "approval_required", "operator_approval_reason",
    "ask_site_for", "do_not", "required_evidence", "missing_information",
})


def _exact_dict(value: Any, keys: frozenset) -> bool:
    return type(value) is dict and set(value) == keys


def _valid_observation_text(
    value: Any,
    max_length: int = 128,
    allow_none: bool = False,
) -> bool:
    if value is None:
        return allow_none
    return (
        type(value) is str
        and 0 < len(value) <= max_length
        and not any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F
            for char in value
        )
        and not _contains_secret_material(value)
    )


def _valid_optional_bool(value: Any) -> bool:
    return value is None or type(value) is bool


def _valid_text_list(value: Any) -> bool:
    return (
        type(value) is list
        and len(value) <= 32
        and all(_valid_observation_text(item) for item in value)
    )


def _valid_optional_enum(value: Any, allowed: frozenset) -> bool:
    return value is None or (type(value) is str and value in allowed)


def _valid_public_network(value: Any, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return (
        type(value) is str
        and _public_observation_network(value, default=None) == value
    )


def _valid_public_asset(value: Any, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return (
        type(value) is str
        and _public_observation_asset(value, default=None) == value
    )


def _valid_public_rail(value: Any, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return type(value) is str and value in _PUBLIC_RAILS


def _valid_public_scheme(value: Any, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return (
        type(value) is str
        and _public_observation_scheme(value, default=None) == value
    )


def _validate_observation_payload(payload: Any) -> Optional[str]:
    """Return a fixed failure code, or ``None`` for the one allowed schema."""
    if not _exact_dict(payload, _OBSERVATION_TOP_LEVEL_KEYS):
        return "observation_schema_invalid"

    # Enforce the byte ceiling before detailed semantic checks. This keeps the
    # resource limit deterministic even for an otherwise ill-formed payload.
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        return "observation_schema_invalid"
    if len(encoded) > MAX_OBSERVATION_PAYLOAD_BYTES:
        return "observation_payload_too_large"
    if _contains_secret_keys(payload) or _contains_secret_material(payload):
        return "observation_secret_material_rejected"

    target_url = payload["targetUrl"]
    if (
        payload["agentId"] != _OBSERVATION_AGENT_ID
        or not _valid_observation_text(target_url, max_length=8192)
        or target_url == QUERY_REDACTION
        or _public_observation_target(target_url) != target_url
        or payload["schema_version"] != "mcp_observation_report.v1"
        or payload["source_channel"] != "mcp"
        or payload["source_scope"] != "external_agent_report"
        or payload["method"] not in {"GET", "HEAD"}
        or type(payload["statusCode"]) is not int
        or not 100 <= payload["statusCode"] <= 599
        or payload["sdk_version"] != _OBSERVATION_SDK_VERSION
    ):
        return "observation_schema_invalid"

    protocol = payload["protocol"]
    if not _exact_dict(protocol, _OBSERVATION_PROTOCOL_KEYS):
        return "observation_schema_invalid"
    if not all(
        _valid_observation_text(protocol[key])
        for key in (
            "rail", "network", "asset", "payment_intent", "payment_method",
            "authorization_scheme", "draft_shape",
        )
    ):
        return "observation_schema_invalid"
    if (
        not _valid_public_rail(protocol["rail"])
        or not _valid_public_network(protocol["network"])
        or not _valid_public_asset(protocol["asset"])
        or _public_observation_intent(protocol["payment_intent"])
        != protocol["payment_intent"]
        or protocol["payment_method"] != "unknown"
        or protocol["authorization_scheme"] != protocol["rail"]
        or protocol["draft_shape"] != "unknown"
    ):
        return "observation_schema_invalid"
    selected = protocol["selected_settlement_option"]
    if selected is not None:
        if not _exact_dict(selected, _OBSERVATION_SELECTED_KEYS):
            return "observation_schema_invalid"
        if not all(
            _valid_observation_text(selected[key], allow_none=True)
            for key in _OBSERVATION_SELECTED_KEYS
        ):
            return "observation_schema_invalid"
        if (
            not _valid_public_network(selected["network"], allow_none=True)
            or not _valid_public_asset(selected["asset"], allow_none=True)
            or not _valid_public_rail(selected["rail"], allow_none=True)
            or not _valid_public_scheme(selected["scheme"], allow_none=True)
        ):
            return "observation_schema_invalid"

    summaries = payload["settlement_options_summary"]
    if type(summaries) is not list or len(summaries) > 32:
        return "observation_schema_invalid"
    text_summary_keys = _OBSERVATION_SUMMARY_KEYS - {
        "selected", "deferred_settlement", "requires_channel_state",
    }
    for summary in summaries:
        if not _exact_dict(summary, _OBSERVATION_SUMMARY_KEYS):
            return "observation_schema_invalid"
        if not all(
            _valid_observation_text(summary[key], allow_none=True)
            for key in text_summary_keys
        ):
            return "observation_schema_invalid"
        if (
            not _valid_public_network(summary["network"], allow_none=True)
            or not _valid_public_asset(summary["asset"], allow_none=True)
            or not _valid_public_rail(summary["rail"], allow_none=True)
            or not _valid_public_scheme(summary["scheme"], allow_none=True)
            or not _valid_optional_enum(
                summary["execution_support"], _PUBLIC_EXECUTION_SUPPORT
            )
            or (
                summary["selection_reason"] is not None
                and _public_selection_reason(summary["selection_reason"])
                != summary["selection_reason"]
            )
            or not _valid_optional_enum(
                summary["settlement_model"], _PUBLIC_SETTLEMENT_MODELS
            )
            or not _valid_optional_enum(
                summary["authorization_artifact"],
                _PUBLIC_AUTHORIZATION_ARTIFACTS,
            )
            or not _valid_optional_enum(
                summary["finality_model"], _PUBLIC_FINALITY_MODELS
            )
        ):
            return "observation_schema_invalid"
        if not all(
            _valid_optional_bool(summary[key])
            for key in ("selected", "deferred_settlement", "requires_channel_state")
        ):
            return "observation_schema_invalid"

    evidence = payload["evidence"]
    if not _exact_dict(evidence, _OBSERVATION_EVIDENCE_KEYS):
        return "observation_schema_invalid"
    if (
        evidence["evidence_class"] != "mcp_inspect_402"
        or evidence["verification_status"] != "unverified"
        or evidence["verification_method"] != "none"
        or evidence["proof_reference"] != "none"
        or evidence["provider_controlled"] is not False
        or evidence["payment_performed"] is not False
        or evidence["payment_receipt_present"] is not False
    ):
        return "observation_safety_invariant_failed"

    handoff = payload["handoff"]
    if not _exact_dict(handoff, _OBSERVATION_HANDOFF_KEYS):
        return "observation_schema_invalid"
    if (
        not _valid_observation_text(handoff["handoff_mode"], allow_none=True)
        or not _valid_optional_enum(handoff["handoff_mode"], _PUBLIC_HANDOFF_MODES)
        or not _valid_optional_bool(handoff["approval_required"])
        or not _valid_observation_text(
            handoff["operator_approval_reason"],
            allow_none=True,
        )
        or not all(
            _valid_text_list(handoff[key])
            for key in (
                "ask_site_for", "do_not", "required_evidence",
                "missing_information",
            )
        )
        or not _valid_optional_enum(
            handoff["operator_approval_reason"], _PUBLIC_OPERATOR_REASONS
        )
        or not all(
            set(handoff[key]).issubset(_PUBLIC_HANDOFF_ITEMS)
            for key in (
                "ask_site_for", "do_not", "required_evidence",
                "missing_information",
            )
        )
    ):
        return "observation_schema_invalid"
    return None


def _submission_result(
    status: str,
    status_code: Optional[int],
    failure_code: Optional[str],
) -> Dict[str, Any]:
    return {
        "status": status,
        "status_code": status_code,
        "failure_code": failure_code,
        "recommended_action": (
            "none" if status == "success" else "stop_safely"
        ),
    }


@mcp.tool()
def submit_mcp_observation(
    payload: Dict[str, Any],
    endpoint: str = CANONICAL_OBSERVATION_ENDPOINT,
) -> Dict[str, Any]:
    """Explicitly submit one validated report to the canonical endpoint."""
    if endpoint != CANONICAL_OBSERVATION_ENDPOINT:
        return _submission_result(
            "failure",
            None,
            "observation_endpoint_mismatch",
        )
    try:
        failure_code = _validate_observation_payload(payload)
        if failure_code is None:
            snapshot = json.loads(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            failure_code = _validate_observation_payload(snapshot)
    except Exception:
        failure_code = "observation_schema_invalid"
    if failure_code is not None:
        return _submission_result(
            "failure",
            None,
            "observation_payload_rejected",
        )

    try:
        payload_json = json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        return _submission_result(
            "failure",
            None,
            "observation_payload_rejected",
        )
    try:
        _validate_observation_target(snapshot["targetUrl"], timeout=5.0)
    except Exception:
        return _submission_result(
            "failure",
            None,
            "observation_target_rejected",
        )
    try:
        status_code = int(
            _submit_observation_request(endpoint, payload_json, timeout=5.0)
        )
    except InspectTransportError as exc:
        return _submission_result("failure", exc.status_code, exc.code)
    except Exception:
        return _submission_result(
            "failure",
            None,
            "observation_delivery_unknown",
        )

    if 200 <= status_code < 300:
        return _submission_result("success", status_code, None)
    return _submission_result("failure", status_code, "observation_http_error")

def main():
    mcp.run()

if __name__ == "__main__":
    main()
