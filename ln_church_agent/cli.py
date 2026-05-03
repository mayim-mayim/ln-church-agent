import argparse
import requests
import httpx
from typing import Optional
from .models import InspectResult
from .challenges import parse_challenge_from_response
from .exceptions import PaymentChallengeError

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
        try:
            httpx_res = _requests_to_httpx_response(res, method)
            parsed = parse_challenge_from_response(httpx_res)
            
            scheme = getattr(parsed, "scheme", "unknown")
            rails = [scheme] if scheme != "unknown" else []
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
            
        except PaymentChallengeError as e:
            return InspectResult(
                ok=True,
                url=url,
                http_status=res.status_code,
                recommended_action="reject_invalid",
                reason=f"Failed to parse challenge: {e}",
                will_execute_payment=False
            )
        except Exception as e:
            return InspectResult(
                ok=False,
                url=url,
                http_status=res.status_code,
                error_stage="parse",
                failure_reason=str(e),
                recommended_action="stop_safely",
                reason="Unexpected error parsing challenge. Stopping safely without payment.",
                will_execute_payment=False
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