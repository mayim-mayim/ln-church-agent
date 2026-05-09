import argparse
import requests
import httpx
import re
from typing import Optional, List
from .models import InspectResult
from .challenges import parse_challenge_from_response
from .exceptions import PaymentChallengeError
from .app_inspect import detect_commerce_surface, detect_app_surface

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
    if scheme == "exact":
        return "x402"
    if scheme == "Payment" and parsed:
        method = getattr(parsed, "payment_method", "").lower()
        if method == "lightning" or parsed.parameters.get("invoice"):
            return "MPP"
        if method in ["eip3009", "exact", "evm", "x402"]:
            return "x402"
        return "unknown"
    if scheme in ["L402", "MPP", "Payment", "x402"]:
        return scheme
    return scheme

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

    # 💡 Commerce Surface の検出
    commerce_info = detect_commerce_surface(httpx_res)

    if commerce_info:
        c_protocol = commerce_info.get("commerce_protocol")
        c_intent = commerce_info.get("commerce_intent")
        
        scheme = getattr(parsed, "scheme", "unknown") if parsed else "unknown"
        s_rail = _settlement_rail_from_scheme(scheme, parsed)
        
        surfaces_detected = []
        settlement_rails_detected = []
        rails_detected = [] 

        # Surface classification
        if c_protocol == "ap2":
            surfaces_detected.append("AP2")
            # rails_detected には入れない
        elif c_protocol == "acp":
            surfaces_detected.append("ACP")
            # rails_detected には入れない
        elif c_protocol == "okx_app":
            surfaces_detected.append("OKX_APP")
            rails_detected.append("APP") # v1.8.0 互換のため維持

        # Settlement rail classification (実行可能なもののみ)
        if scheme == "Payment":
            # rails_detected に Payment を残すのは互換性のため許容
            rails_detected.append("Payment") 
            if s_rail and s_rail not in ["Payment", "unknown"]:
                settlement_rails_detected.append(s_rail)
                rails_detected.append(s_rail)
        elif s_rail and s_rail != "unknown":
            settlement_rails_detected.append(s_rail)
            rails_detected.append(s_rail)

        action = "observe_only"
        unsupported_reason = None

        if c_protocol in ["ap2", "acp"]:
            reason = commerce_info.get("reason", "Agent Commerce surface detected.")
            has_payment_headers = any(h.lower() in ["www-authenticate", "payment-required", "x-payment-required", "x-402-payment-required"] for h in httpx_res.headers.keys())
            is_malformed_hint = False
            
            if parse_error and has_payment_headers:
                is_malformed_hint = True
            elif scheme != "unknown" and s_rail not in ["x402", "L402", "MPP", "Payment"]:
                is_malformed_hint = True

            if is_malformed_hint:
                action = "stop_safely"
                unsupported_reason = "Malformed or unsupported settlement hint co-existing with commerce surface."
            else:
                action = "observe_only"
                if settlement_rails_detected:
                    reason += " (Concrete HTTP 402 settlement challenge also detected, but payment is not executed by default for AP2/ACP)."
        else:
            # 💡 修正: OKX APP のレガシー互換（既存テストがこの固定文字列を期待しているため元に戻す）
            reason = "Agent Commerce surface detected."
            if c_intent in ["session", "escrow", "upto"]:
                action = "stop_safely"
                reason = f"High-intent commerce flow ({c_intent}) observed but not executed by default."

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
            app_transport=commerce_info.get("commerce_transport", "http")
        )

    # --- Commerce Surface ではない既存ロジック ---
    if res.status_code < 400 and res.status_code != 402:
        return InspectResult(
            ok=True,
            url=url,
            http_status=res.status_code,
            recommended_action="no_payment_required",
            reason="No HTTP 402 payment challenge detected.",
            will_execute_payment=False
        )

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
                will_execute_payment=False
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

        if intent == "session":
            action = "stop_safely"
            reason = "MPP session execution is observed but not executed by default."
            next_cmd = None
        elif scheme == "exact":
            action = "observe_only"
            diagnostic_class = "post_settlement_proof_required"
            reason = "This endpoint exposes an x402 exact challenge but validates only post-settlement evidence. The SDK-generated unbroadcasted exact payload will be rejected unless a submitted tx hash/signature is provided."
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
            diagnostic_class=diagnostic_class
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
            if result.next_command:
                print(f"  Next Command       : {result.next_command}")
            if getattr(result, "diagnostic_class", None):
                print(f"  Diagnostic Class   : {result.diagnostic_class}")
            if not result.ok and result.failure_reason:
                print(f"  Failure            : {result.error_stage} -> {result.failure_reason}")

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