import argparse
import requests
import httpx
import re
import os
import json
from typing import Optional, List, Tuple
from .models import InspectResult, SettlementOption, ObservatoryMetadata
from .challenges import parse_challenge_from_response
from .exceptions import PaymentChallengeError
from .app_inspect import detect_commerce_surface, detect_app_surface, build_commerce_guidance
from .failures import fingerprint_public_challenge_summary
from .grant_signals import detect_grant_signals
from .models import GrantSignalObservation

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

    settlement_opts = []
    selected_opt = None
    if parsed:
        settlement_opts, selected_opt = _extract_settlement_options(parsed)

    commerce_info = detect_commerce_surface(httpx_res)

    try:
        grant_signals = detect_grant_signals(httpx_res)
    except Exception:
        grant_signals = GrantSignalObservation()

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
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    if res.status_code < 400 and res.status_code != 402:
        return InspectResult(
            ok=True,
            url=url,
            http_status=res.status_code,
            recommended_action="no_payment_required",
            reason="No HTTP 402 payment challenge detected.",
            will_execute_payment=False,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
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
                will_execute_payment=False,
                ln_church_observatory=ObservatoryMetadata(),
                grant_signal_detected=grant_signals.detected,
                grant_signals=grant_signals
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
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    return InspectResult(
        ok=False,
        url=url,
        http_status=res.status_code,
        recommended_action="unknown",
        reason=f"Unexpected HTTP status {res.status_code}.",
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