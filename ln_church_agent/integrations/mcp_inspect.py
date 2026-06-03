import json
from typing import Dict, Any, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError("Install with `pip install ln-church-agent[mcp]`")

from ..cli import inspect_url
from ..client import SDK_VERSION

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
            "pay_to": opt.pay_to,
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

    return {
        "schema_version": "ln_church_agent.mcp.inspect_result.v1",
        "url": url,
        "method": method.upper(),
        "status_code": result.http_status,
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
        "grant_signals": result.grant_signals.model_dump() if getattr(result, "grant_signals", None) else None,
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
    action = inspect_result.get("recommended_action", "unknown")
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

    handoff_mode = inspect_result.get("handoff_mode")
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
        "approval_required": inspect_result.get("approval_required"),
        "operator_approval_reason": inspect_result.get("operator_approval_reason"),
        "ask_site_for": inspect_result.get("ask_site_for", []),
        "do_not": inspect_result.get("do_not", []),
        "required_evidence": inspect_result.get("required_evidence", []),
        "missing_information": inspect_result.get("missing_information", [])
    }

@mcp.tool()
def build_mcp_observation_payload(inspect_result: Dict[str, Any], agent_id: str = "optional-agent-id") -> Dict[str, Any]:
    """
    Builds a telemetry observation payload for external observation endpoints.
    Does NOT auto-submit. Guaranteed to have secrets redacted and payment_performed=false.
    """
    rails = inspect_result.get("settlement_rails_detected", [])
    rail = rails[0] if rails else "unknown"
    
    network = "unknown"
    asset = "unknown"
    
    selected_opt = inspect_result.get("selected_settlement_option")
    opts = inspect_result.get("settlement_options", [])
    
    if selected_opt:
        network = selected_opt.get("network") or "unknown"
        asset = selected_opt.get("asset") or "unknown"
    elif opts:
        network = opts[0].get("network") or "unknown"
        asset = opts[0].get("asset") or "unknown"
    else:
        network = inspect_result.get("network") or "unknown"
        
    options_summary = []
    for opt in opts:
        options_summary.append({
            "network": opt.get("network"),
            "asset": opt.get("asset"),
            "rail": opt.get("rail"),
            "scheme": opt.get("scheme"),
            "selected": opt.get("selected"),
            "execution_support": opt.get("execution_support"),
            "selection_reason": opt.get("selection_reason"),
            "settlement_model": opt.get("settlement_model"),
            "authorization_artifact": opt.get("authorization_artifact"),
            "finality_model": opt.get("finality_model"),
            "deferred_settlement": opt.get("deferred_settlement"),
            "requires_channel_state": opt.get("requires_channel_state")
        })
    
    # (v1.11.2)
    # Grant-like signals are intentionally excluded from external observation payloads for now.
    # They are local inspect-only sidecar signals, not Hon-den observation facts.
    return {
        "schema_version": "mcp_observation_report.v1",
        "agentId": agent_id,
        "targetUrl": inspect_result.get("url", "unknown"),
        "source_channel": "mcp",
        "source_scope": "external_agent_report",
        "method": inspect_result.get("method", "GET"),
        "statusCode": inspect_result.get("status_code", 402),
        "protocol": {
            "rail": rail,
            "network": network,
            "asset": asset,
            "payment_intent": inspect_result.get("commerce_intent", "unknown"),
            "payment_method": "unknown",
            "authorization_scheme": rail,
            "draft_shape": "unknown",
            "selected_settlement_option": {
                "network": network,
                "asset": asset,
                "rail": selected_opt.get("rail") if selected_opt else None,
                "scheme": selected_opt.get("scheme") if selected_opt else None,
            } if selected_opt else None
        },
        # 💡 Nice to have: Payload Top-Level へ移動
        "settlement_options_summary": options_summary,
        "evidence": {
            "evidence_class": "mcp_inspect_402",
            "verification_status": "unverified",
            "verification_method": "none",
            "proof_reference": "none",
            "provider_controlled": False,
            "payment_performed": False,
            "payment_receipt_present": False
        },
        "handoff": {
            "handoff_mode": inspect_result.get("handoff_mode"),
            "approval_required": inspect_result.get("approval_required"),
            "operator_approval_reason": inspect_result.get("operator_approval_reason"),
            "ask_site_for": inspect_result.get("ask_site_for", []),
            "do_not": inspect_result.get("do_not", []),
            "required_evidence": inspect_result.get("required_evidence", []),
            "missing_information": inspect_result.get("missing_information", [])
        },
        "sdk_version": SDK_VERSION
    }

@mcp.tool()
def submit_mcp_observation(payload: Dict[str, Any], endpoint: str = "https://kari.mayim-mayim.com/api/agent/external/mcp-observe") -> Dict[str, Any]:
    """
    Explicitly submits a previously built MCP observation payload.
    Strictly verifies that no payments were performed and no secrets are leaked.
    """
    evidence = payload.get("evidence", {})
    if evidence.get("payment_performed", True):
        return {"error": "Safety violation: payment_performed must be strictly false."}
        
    proof_ref = evidence.get("proof_reference", "none")
    if proof_ref != "none" and len(str(proof_ref)) > 64: 
        return {"error": "Safety violation: proof_reference looks like a raw secret."}
    # Recursive check for exact secret key matches
    if _contains_secret_keys(payload):
        return {"error": "Safety violation: potential secret leaked in payload keys."}

    try:
        import requests
        res = requests.post(endpoint, json=payload, timeout=5)
        return {"status": "success", "status_code": res.status_code, "response": res.text}
    except Exception as e:
        return {"error": "Submission failed", "reason": str(e)}

def main():
    mcp.run()

if __name__ == "__main__":
    main()