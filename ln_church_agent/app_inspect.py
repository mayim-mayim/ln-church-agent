import httpx
import re
from typing import Optional, Dict, Any, List
from .challenges import b64url_decode_json

def _extract_json_payloads(response: httpx.Response) -> List[Dict[str, Any]]:
    payloads = []
    try:
        body = response.json()
        if isinstance(body, dict):
            payloads.append(body)
    except Exception:
        pass

    for header, value in response.headers.items():
        h_lower = header.lower()
        if h_lower in ["payment-required", "www-authenticate", "x-agent-payment"]:
            match = re.search(r'request="?([^",]+)"?', value)
            if match:
                b64_val = match.group(1)
                decoded = b64url_decode_json(b64_val)
                if decoded:
                    payloads.append(decoded)
            else:
                decoded = b64url_decode_json(value)
                if decoded:
                    payloads.append(decoded)
                    
    return payloads

def _is_x_layer_network(value: Any) -> bool:
    s = str(value).lower().strip()
    return s in {"196", "eip155:196", "xlayer", "x-layer"}

def detect_commerce_surface(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """
    Agent Commerce surface (AP2, ACP, OKX APP 等) を検出・分類する。
    AP2/ACP は settlement proof ではなく commerce/authorization surface として扱う。
    """
    payloads = _extract_json_payloads(response)
    if not payloads:
        return None

    merged = {}
    for p in payloads:
        merged.update(p)

    proto = str(merged.get("protocol") or merged.get("agentPaymentsProtocol") or "").lower()
    intent = str(merged.get("intent") or merged.get("paymentIntent") or "").lower()

    # --- 1. AP2 Detection & Artifact Classification ---
    is_ap2 = False
    if proto in ["ap2", "agent-payments-protocol"]: is_ap2 = True
    if any(k in merged for k in ["payment_mandate", "checkout_mandate", "mandate_id", "mandate.vct"]): is_ap2 = True
    if intent in ["payment_mandate", "checkout_mandate", "mandate"]: is_ap2 = True

    if is_ap2:
        # Artifact 分類
        art = "payment_mandate"
        if intent == "checkout_mandate" or "checkout_mandate" in merged:
            art = "checkout_mandate"
        
        return {
            "commerce_protocol": "ap2",
            "surface_type": "authorization",
            "commerce_intent": intent if intent else "payment_mandate",
            "authorization_artifact": art,
            "confidence": "high",
            "reason": "AP2-like mandate metadata detected",
            "commerce_transport": "http",
            "raw_detected_fields": merged
        }

    # --- 2. ACP Detection & Artifact Classification ---
    is_acp = False
    if proto in ["acp", "agentic commerce protocol", "agentic-commerce-protocol"]: is_acp = True
    if any(k in merged for k in ["delegate_payment", "delegated_payment", "shared_payment_token"]): is_acp = True
    if intent in ["agentic_checkout", "cart", "catalog", "delegated_payment"]: is_acp = True

    if is_acp:
        # Artifact 分類
        art = "delegated_payment_token" # Default for delegated_payment
        if intent == "catalog":
            art = "none"
        elif "shared_payment_token" in merged:
            art = "shared_payment_token"
        
        surface_type = "catalog" if intent == "catalog" else "checkout"
        return {
            "commerce_protocol": "acp",
            "surface_type": surface_type,
            "commerce_intent": intent if intent else "agentic_checkout",
            "authorization_artifact": art,
            "confidence": "high",
            "reason": "ACP-like checkout or delegated payment metadata detected",
            "commerce_transport": "http",
            "raw_detected_fields": merged
        }

    # --- 3. OKX APP (Legacy) Detection ---
    score = 0
    is_explicit_signal = False
    if proto in ["okx-app", "app"]:
        score += 50
        is_explicit_signal = True
    
    broker = merged.get("broker")
    broker_req = None
    if isinstance(broker, dict):
        score += 30
        is_explicit_signal = True
        broker_req = bool(broker.get("required"))
        
    if intent in ["batch", "escrow", "upto"]:
        score += 30
        is_explicit_signal = True
    elif intent in ["charge", "session"]:
        score += 5
        
    payment = merged.get("payment") or merged.get("settlement") or {}
    if not isinstance(payment, dict): payment = {}
    method = payment.get("method") or merged.get("method")
    settlement_method = "evm_eip3009" if str(method).lower() == "eip3009" else str(method) if method else "unknown"
    net = payment.get("network") or merged.get("network") or merged.get("chainId")
    network_val = str(net) if net else "unknown"

    if is_explicit_signal and score >= 30:
        return {
            "commerce_protocol": "okx_app",
            "surface_type": "app_payment",
            "commerce_intent": intent if intent else "unknown",
            "commerce_transport": "http",
            "authorization_artifact": "none",
            "confidence": "high" if score >= 50 else "medium",
            "reason": "OKX APP metadata detected",
            "broker_required": broker_req,
            "settlement_method": settlement_method,
            "network": network_val,
            "raw_detected_fields": merged
        }

    return None

def detect_app_surface(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """Legacy wrapper for v1.8 backward compatibility"""
    res = detect_commerce_surface(response)
    if res and res.get("commerce_protocol") == "okx_app":
        return res
    return None

def build_commerce_guidance(
    commerce_protocol: Optional[str],
    raw_fields: Dict[str, Any]
) -> Dict[str, Any]:
    if not commerce_protocol:
        return {}
        
    guidance = {
        "handoff_mode": "guided_handoff",
        "approval_required": True,
        "ask_site_for": [],
        "do_not": [],
        "required_evidence": [],
        "missing_information": [],
    }

    # 💡 v1.9.5: Check for explicit settlement hints in the raw payload
    has_settlement_hint = any(k in raw_fields for k in ["network", "chainId", "asset", "currency", "scheme", "paymentMethod", "accepts", "payment"])

    if commerce_protocol == "ap2":
        guidance["ask_site_for"] = [
            "quote_details", "mandate_scope", "expiration", "revocation_method", "settlement_rail_options", "receipt_or_proof_model"
        ]
        guidance["do_not"] = [
            "treat_mandate_as_settlement_proof", "execute_payment_without_operator_approval", "store_raw_mandate_payload"
        ]
        guidance["required_evidence"] = [
            "explicit_price", "merchant_identity", "mandate_scope", "settlement_rail", "receipt_model"
        ]
        if "amount" not in raw_fields and "price" not in raw_fields:
            guidance["missing_information"].append("explicit_price")
        if "merchant" not in raw_fields and "payTo" not in raw_fields and "merchant_id" not in raw_fields:
            guidance["missing_information"].append("merchant_identity")

    elif commerce_protocol == "acp":
        guidance["ask_site_for"] = [
            "cart_details", "price_breakdown", "merchant_identity", "checkout_expiration", "payment_token_scope", "settlement_rail_options", "order_receipt_model"
        ]
        guidance["do_not"] = [
            "treat_shared_payment_token_as_settlement_proof", "execute_checkout_without_operator_approval", "store_raw_shared_payment_token"
        ]
        guidance["required_evidence"] = [
            "cart_total", "merchant_identity", "payment_token_scope", "order_receipt", "settlement_rail"
        ]
        if "cart_total" not in raw_fields and "amount" not in raw_fields and "price" not in raw_fields:
            guidance["missing_information"].append("cart_total")
        if "merchant" not in raw_fields and "payTo" not in raw_fields and "merchant_id" not in raw_fields:
            guidance["missing_information"].append("merchant_identity")

    elif commerce_protocol == "okx_app":
        guidance["ask_site_for"] = [
            "quote_details", "broker_identity", "escrow_terms", "settlement_method", "dispute_policy", "receipt_or_proof_model"
        ]
        guidance["do_not"] = [
            "treat_broker_hint_as_settlement_proof", "enter_escrow_without_operator_approval", "store_raw_broker_or_session_token"
        ]
        guidance["required_evidence"] = [
            "quote", "broker_identity", "settlement_method", "escrow_or_dispute_terms", "receipt_model"
        ]
        if "broker" not in raw_fields and "broker_id" not in raw_fields:
            guidance["missing_information"].append("broker_identity")
        if "amount" not in raw_fields and "quote" not in raw_fields:
            guidance["missing_information"].append("quote")

    # 💡 v1.9.5: Native injection of missing settlement boundaries if no hints exist
    if not has_settlement_hint:
        guidance["missing_information"].extend([
            "settlement_rail_not_declared",
            "network_not_declared",
            "asset_not_declared",
            "post_payment_artifact_unknown"
        ])

    # 重複排除
    guidance["missing_information"] = list(dict.fromkeys(guidance["missing_information"]))

    return guidance