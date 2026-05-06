import argparse
import requests
import httpx
from typing import Optional, List
from .models import InspectResult
from .challenges import parse_challenge_from_response
from .exceptions import PaymentChallengeError
from .app_inspect import detect_app_surface

def _requests_to_httpx_response(req_res: requests.Response, method: str = "GET") -> httpx.Response:
    """requests のレスポンスをパーサーが期待する httpx の形に変換する内部ヘルパー"""
    try:
        content = req_res.content
    except Exception:
        content = b""
    return httpx.Response(
        status_code=req_res.status_code,
        headers=req_res.headers,
        content=content,
        request=httpx.Request(method.upper(), req_res.url)
    )

def _settlement_rail_from_scheme(scheme: str) -> Optional[str]:
    """スキーム名から決済レール名への正規化"""
    if scheme == "exact":
        return "x402"
    if scheme in ["L402", "MPP", "Payment"]:
        return scheme
    return scheme if scheme and scheme != "unknown" else None

def inspect_url(url: str, method: str = "GET", timeout: int = 10) -> InspectResult:
    """指定URLに対して無支払いの検査リクエストを送り、チャレンジの構造を判定する"""
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

    httpx_res = _requests_to_httpx_response(res, method)

    # 1. 既存の Payment Challenge の解析を先に行う
    parsed = None
    parse_error = None
    if res.status_code in (402, 401, 403):
        try:
            parsed = parse_challenge_from_response(httpx_res)
        except Exception as e:
            parse_error = str(e)

    # 2. Commerce Surface (APP 等) の検出
    app_info = detect_app_surface(httpx_res)

    # 3. Commerce Surface が検出された場合
    if app_info:
        scheme = getattr(parsed, "scheme", "unknown") if parsed else "unknown"
        s_rail = _settlement_rail_from_scheme(scheme)
        
        rails_detected = ["APP"]
        if s_rail:
            rails_detected.append(s_rail)

        c_intent = app_info.get("commerce_intent")
        action = "observe_only"
        reason = "Agent Commerce surface detected. Inspect-only mode does not execute commerce payments yet."

        if c_intent in ["session", "escrow", "upto"]:
            action = "stop_safely"
            reason = f"High-intent commerce flow ({c_intent}) observed but not executed by default."

        return InspectResult(
            ok=True,
            url=url,
            http_status=res.status_code,
            rails_detected=rails_detected,
            recommended_action=action,
            reason=reason,
            will_execute_payment=False,
            diagnostic_class="commerce_surface_detected",
            commerce_protocol=app_info.get("commerce_protocol"),
            commerce_intent=c_intent,
            commerce_transport=app_info.get("commerce_transport"),
            authorization_artifact=None,
            settlement_rail=s_rail,
            settlement_method=app_info.get("settlement_method"),
            network=app_info.get("network"),
            broker_required=app_info.get("broker_required"),
            classification_confidence=app_info.get("confidence"),
            # 互換用エイリアス
            app_protocol=app_info.get("commerce_protocol"),
            app_intent=c_intent,
            app_transport=app_info.get("commerce_transport"),
            # 💡 APP検出時はトップレベルのエラーは出さない（紛らわしさを排除）
            error_stage=None,
            failure_reason=None
        )

    # 4. Commerce Surface が検出されなかった場合の既存ロジック
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
            if "No valid 402" in parse_error or "Failed to parse" in parse_error:
                return InspectResult(
                    ok=True,
                    url=url,
                    http_status=res.status_code,
                    recommended_action="reject_invalid",
                    reason=f"Failed to parse challenge: {parse_error}",
                    will_execute_payment=False
                )
            else:
                return InspectResult(
                    ok=False,
                    url=url,
                    http_status=res.status_code,
                    error_stage="parse",
                    failure_reason=parse_error,
                    recommended_action="stop_safely",
                    reason="Unexpected error parsing challenge. Stopping safely.",
                    will_execute_payment=False
                )

        scheme = getattr(parsed, "scheme", "unknown")
        s_rail = _settlement_rail_from_scheme(scheme)
        rails = [s_rail] if s_rail else []
        
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
            reason = "Challenge shape is incomplete or invalid."
            next_cmd = None

        return InspectResult(
            ok=True,
            url=url,
            http_status=res.status_code,
            rails_detected=rails,
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
            print(f"  Reason             : {result.reason}")
            if result.next_command:
                print(f"  Next Command       : {result.next_command}")
            if getattr(result, "diagnostic_class", None):
                print(f"  Diagnostic Class   : {result.diagnostic_class}")
            if not result.ok and result.failure_reason:
                print(f"  Failure            : {result.error_stage} -> {result.failure_reason}")

if __name__ == "__main__":
    main()