import argparse
import requests
import httpx
import re
from typing import Optional, List, Tuple
from .models import InspectResult, SettlementOption, ObservatoryMetadata
from .challenges import parse_challenge_from_response
from .exceptions import PaymentChallengeError
from .app_inspect import detect_commerce_surface, detect_app_surface, build_commerce_guidance
from .failures import fingerprint_public_challenge_summary

def _requests_to_httpx_response(req_res: requests.Response, method: str = "GET") -> httpx.Response:
    try:
        content = req_res.content or b""
    except Exception:
        content = b""

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
    if not scheme or scheme.lower() == "unknown":
        return "unknown"
    if scheme in ["exact", "batch-settlement", "auth-capture"]:
        return "x402"
    if scheme == "Payment" and parsed:
        method = getattr(parsed, "payment_method", "").lower()
        if method == "lightning" or parsed.parameters.get("invoice"):
            return "MPP"
        if method in ["eip3009", "exact", "evm", "x402", "batch-settlement", "auth-capture"]:
            return "x402"
        return "unknown"
    if scheme in ["L402", "MPP", "Payment", "x402"]:
        return scheme
    return scheme

CHAIN_HINTS = {
    "1": "Ethereum",
    "137": "Polygon",
    "8453": "Base",
    "196": "X Layer",
    "11155111": "Ethereum Sepolia"
}

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
    raw_accepted = parsed.parameters.get("_raw_accepted")
    all_accepted = parsed.parameters.get("_all_accepted", [])
    reason_from_parser = parsed.parameters.get("_selection_reason", "unknown")

    if not all_accepted and parsed.scheme in ["L402", "MPP", "Payment"]:
        cf, ch = _determine_chain_info(parsed.network)
        rail = _settlement_rail_from_scheme(parsed.scheme, parsed) or parsed.scheme
        opt = SettlementOption(
            rail=rail,
            scheme=parsed.scheme,
            network=parsed.network,
            chain_family=cf,
            chain_name_hint=ch,
            asset=parsed.asset,
            amount=str(parsed.amount) if parsed.amount else None,
            pay_to=parsed.parameters.get("destination") or parsed.parameters.get("invoice"),
            source="www_authenticate",
            execution_support="supported_but_not_executed_in_inspect" if rail in ["L402", "MPP"] else "unknown",
            selected=True,
            selection_reason="single_option_provided"
        )
        return [opt], opt

    for idx, req in enumerate(all_accepted):
        net = req.get("network", "unknown")
        cf, ch = _determine_chain_info(net)
        sch = req.get("scheme", "exact")
        
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

        raw_amt = str(req.get("amount") or req.get("maxAmountRequired", ""))
        asset_val = req.get("symbol") or req.get("asset") or req.get("token") or req.get("mint")
        
        opt = SettlementOption(
            rail="x402",
            scheme=sch,
            network=net,
            chain_family=cf,
            chain_name_hint=ch,
            asset=asset_val,
            amount=raw_amt,
            amount_atomic=raw_amt,
            pay_to=req.get("payTo"),
            source=f"accepts[{idx}]",
            raw_requirement_fingerprint=fingerprint_public_challenge_summary(req),
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

def inspect_url(url: str, method: str = "GET", timeout: int = 10) -> InspectResult:
    try:
        res = requests.request(method, url, timeout=timeout)
    except Exception as e:
        return InspectResult(
            ok=False,
            url=url,
            error_stage="fetch",
            failure_reason=str(e),
            recommended_action="stop_safely",
            reason="Network error during inspection.",
            will_execute_payment=False
        )

    try:
        httpx_res = _requests_to_httpx_response(res, method)
    except Exception as e:
        is_402 = res.status_code in (402, 401, 403)
        return InspectResult(
            ok=is_402,
            url=url,
            http_status=res.status_code,
            error_stage="response_adapter",
            failure_class="requests_to_httpx_conversion_failed",
            diagnostic_class="response_decoding_error",
            failure_reason=str(e),
            recommended_action="observe_only" if is_402 else "stop_safely",
            reason=f"Failed to adapt HTTP response: {str(e)}",
            will_execute_payment=False
        )

    parsed = None
    parse_error = None
    if res.status_code in (402, 401, 403):
        try:
            parsed = parse_challenge_from_response(httpx_res)
        except Exception as e:
            parse_error = str(e)

    # 💡 v1.9.5: 実行パスに影響を与えず Settlement Options の全抽出を行う
    settlement_opts = []
    selected_opt = None
    if parsed:
        settlement_opts, selected_opt = _extract_settlement_options(parsed)

    # 💡 Commerce Surface の検出
    commerce_info = detect_commerce_surface(httpx_res)

    # 💡 1. Commerce Surface Block
    if commerce_info:
        c_protocol = commerce_info.get("commerce_protocol")
        c_intent = commerce_info.get("commerce_intent")
        
        scheme = getattr(parsed, "scheme", "unknown") if parsed else "unknown"
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
        
        if parse_error and has_payment_headers:
            is_malformed_hint = True
        elif scheme != "unknown" and s_rail not in ["x402", "L402", "MPP", "Payment"]:
            is_malformed_hint = True

        if is_malformed_hint:
            action = "stop_safely"
            unsupported_reason = "Malformed or unsupported settlement hint co-existing with commerce surface."
            operator_approval_reason = "malformed_or_unsupported_settlement_hint"
            reason = "Agent Commerce surface detected, but co-existing settlement hint is malformed or unsupported."
        # 💡 正しい位置への no_allowed_network_match の組み込み
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

        guidance = build_commerce_guidance(c_protocol, commerce_info.get("raw_detected_fields", {}))

        # 💡 v1.9.5: APP/AP2/ACP で明確な決済オプション(Settlement Options)がない場合、missing_information を補強する
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
            url=url,
            http_status=res.status_code,
            rails_detected=rails_detected,
            surfaces_detected=surfaces_detected,
            settlement_rails_detected=settlement_rails_detected,
            surface_type=commerce_info.get("surface_type"),
            detection_confidence=commerce_info.get("confidence"),
            detection_reason=commerce_info.get("reason"),
            unsupported_reason=unsupported_reason,
            recommended_action=action,
            reason=reason,
            will_execute_payment=False,
            diagnostic_class="commerce_surface_detected",
            commerce_protocol=c_protocol,
            commerce_intent=c_intent,
            commerce_transport=commerce_info.get("commerce_transport", "http"),
            authorization_artifact=commerce_info.get("authorization_artifact"),
            settlement_rail=s_rail if s_rail != "unknown" else None,
            settlement_method=commerce_info.get("settlement_method"),
            network=commerce_info.get("network"),
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
            # --- v1.9.5 New Fields ---
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata()
        )

    # --- Commerce Surface ではない既存ロジック ---
    if res.status_code < 400 and res.status_code != 402:
        return InspectResult(
            ok=True,
            url=url,
            http_status=res.status_code,
            recommended_action="no_payment_required",
            reason="No HTTP 402 payment challenge detected.",
            will_execute_payment=False,
            ln_church_observatory=ObservatoryMetadata()
        )

    # 💡 2. Standard Block
    if res.status_code in (402, 401, 403):
        if parse_error:
            is_invalid_challenge = "No valid 402" in parse_error or "Failed to parse" in parse_error
            
            if "No valid 402" in parse_error:
                diag_cls = "unsupported_challenge_shape"
                fail_cls = "no_valid_challenge"
            elif "Failed to parse" in parse_error:
                diag_cls = "invalid_payment_auth_request"
                fail_cls = "parse_failure"
            else:
                diag_cls = "x402_parse_error"
                fail_cls = "unexpected_error"
            
            return InspectResult(
                ok=is_invalid_challenge,
                url=url,
                http_status=res.status_code,
                error_stage="parse",
                failure_reason=parse_error,
                diagnostic_class=diag_cls,
                failure_class=fail_cls,
                recommended_action="reject_invalid" if is_invalid_challenge else "stop_safely",
                reason=f"Failed to parse challenge: {parse_error}" if is_invalid_challenge else f"Unexpected error parsing challenge: {parse_error}",
                will_execute_payment=False,
                ln_church_observatory=ObservatoryMetadata()
            )

        scheme = getattr(parsed, "scheme", "unknown")
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
        
        intent = getattr(parsed, "payment_intent", None)
        shape = getattr(parsed, "draft_shape", None)
        source = getattr(parsed, "source", None)

        action = "pay_and_verify"
        reason = "Payment challenge detected. Inspect-only mode does not execute payments."
        next_cmd = None  
        diagnostic_class = None

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
            reason = "This endpoint exposes an x402 exact challenge but validates only post-settlement evidence. The SDK-generated unbroadcasted exact payload will be rejected unless a submitted tx hash/signature is provided."
            next_cmd = None
        elif scheme == "batch-settlement":
            action = "observe_only"
            diagnostic_class = "deferred_batch_settlement_observed"
            reason = "x402 batch-settlement challenge detected. Request-time voucher / authorization artifact is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign vouchers or deposit funds."
            next_cmd = None
        elif scheme == "auth-capture":
            action = "observe_only"
            diagnostic_class = "deferred_auth_capture_observed"
            reason = "x402 auth-capture challenge detected. Authorization signature is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign, capture, void, refund, or reclaim."
            next_cmd = None
        elif shape in ["payment-auth-draft-partial", "payment-auth-draft-invalid-request"]:
            action = "reject_invalid"
            diagnostic_class = "invalid_payment_auth_request"
            reason = "Challenge shape is incomplete or invalid."
            next_cmd = None
        elif scheme == "Payment" and s_rail == "unknown":
            action = "observe_only"
            diagnostic_class = "unsupported_challenge_shape"
            reason = "Payment scheme detected but payment method is unknown. Cannot map to a settlement rail."

        return InspectResult(
            ok=True,
            url=url,
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
            # --- v1.9.5 New Fields ---
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata()
        )

    return InspectResult(
        ok=False,
        url=url,
        http_status=res.status_code,
        recommended_action="unknown",
        reason=f"Unexpected HTTP status {res.status_code}.",
        will_execute_payment=False
    )

def main():
    parser = argparse.ArgumentParser(description="ln-church-agent CLI - Agentic Payment Runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect an HTTP 402 endpoint without paying")
    inspect_parser.add_argument("url", type=str, help="Target URL")
    inspect_parser.add_argument("--method", type=str, default="GET", help="HTTP method (default: GET)")
    inspect_parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    inspect_parser.add_argument("--json", action="store_true", help="Output result as JSON")
    
    grant_parser = subparsers.add_parser("grant", help="Manage and inspect grant tokens")
    grant_subparsers = grant_parser.add_subparsers(dest="grant_command", required=True)
    
    grant_inspect_parser = grant_subparsers.add_parser("inspect", help="Inspect a grant token locally without sending it")
    grant_inspect_parser.add_argument("--token", type=str, required=True, help="JWS Grant Token")
    grant_inspect_parser.add_argument("--agent-id", type=str, required=True, help="Expected Agent ID")
    grant_inspect_parser.add_argument("--route", type=str, default="/api/agent/omikuji", help="Target route")
    grant_inspect_parser.add_argument("--method", type=str, default="POST", help="Target HTTP method")
    grant_inspect_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="Target base URL")

    args = parser.parse_args()

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
            
            # 💡 v1.9.5: settlement_options が複数ある場合の表示を追加
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

            # 💡 v1.9.5: 人間向けの軽い導線を末尾に追加
            print("\n---------------------------------------------------------")
            print("💡 Observation generated locally. This result was not submitted.")
            print("To contribute a redacted observation to the public corpus, use an explicit opt-in submission flow.")
            print("LN Church Observatory collects agent-readable evidence for HTTP 402 / x402 / L402 / MPP payment surfaces.")
            print("---------------------------------------------------------")

    if args.command == "grant" and args.grant_command == "inspect":
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

if __name__ == "__main__":
    main()