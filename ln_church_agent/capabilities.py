from typing import List, Dict, Any

def get_capability_matrix() -> List[Dict[str, Any]]:
    """
    Returns the static capability matrix of the ln-church-agent SDK.
    This describes the support boundaries, inspect behaviors, and proof semantics
    for various settlement rails and commerce surfaces.
    This is read-only, non-executing, and performs no network calls.
    """
    return [
        {
            "id": "l402",
            "name": "L402",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "mpp_charge",
            "name": "MPP charge",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "mpp_session_intent",
            "name": "MPP session intent",
            "layer": "settlement_rail",
            "current_sdk_support": "stop_safely",
            "inspect_behavior": "stop_safely",
            "execution_behavior": "halt",
            "proof_semantics": "unverified",
            "default_recommended_action": "stop_safely",
            "watchlist_status": "watch_only"
        },
        {
            "id": "payment_draft_challenge",
            "name": "Payment draft challenge",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_v1_evm",
            "name": "x402 V1 EVM",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_v2_exact_evm",
            "name": "x402 V2 exact EVM",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_v2_exact_svm",
            "name": "x402 V2 exact SVM",
            "layer": "settlement_rail",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "supported_but_not_executed_in_inspect",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "pay_and_verify",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_exact_post_settlement",
            "name": "x402 exact post-settlement diagnostic endpoint",
            "layer": "settlement_rail",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "post_settlement_proof_required",
            "default_recommended_action": "observe_only",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_batch_settlement",
            "name": "x402 batch-settlement",
            "layer": "settlement_rail",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "deferred_voucher_not_settlement_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "implemented"
        },
        {
            "id": "x402_auth_capture",
            "name": "x402 auth-capture",
            "layer": "settlement_rail",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "authorization_signature_not_settlement_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "grant_sponsored_access",
            "name": "Grant / Sponsored Access",
            "layer": "authorization_artifact",
            "current_sdk_support": "executable_now",
            "inspect_behavior": "inspect_supported",
            "execution_behavior": "execute",
            "proof_semantics": "verified",
            "default_recommended_action": "use_grant",
            "watchlist_status": "implemented"
        },
        {
            "id": "grant_like_signal_detection",
            "name": "Grant-like Signal Detection",
            "layer": "incentive_signal",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "sidecar_detection",
            "execution_behavior": "none",
            "proof_semantics": "unverified_signal_not_grant_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "experimental"
        },
        {
            "id": "external_observation",
            "name": "External Observation",
            "layer": "observation",
            "current_sdk_support": "explicit_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "unverified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "implemented"
        },
        {
            "id": "sandbox_evidence",
            "name": "Sandbox Evidence",
            "layer": "observation",
            "current_sdk_support": "explicit_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "unverified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "implemented"
        },
        {
            "id": "goal_attempt_observation",
            "name": "Goal Attempt Observation",
            "layer": "memory",
            "current_sdk_support": "explicit_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "unverified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "implemented"
        },
        {
            "id": "ap2",
            "name": "AP2",
            "layer": "commerce_surface",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "authorization_or_commerce_artifact_not_settlement_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "acp",
            "name": "ACP",
            "layer": "commerce_surface",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "authorization_or_commerce_artifact_not_settlement_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "okx_app",
            "name": "OKX APP",
            "layer": "commerce_surface",
            "current_sdk_support": "observe_only",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "authorization_or_commerce_artifact_not_settlement_proof",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "unknown_unmapped",
            "name": "Unknown / unmapped payment surfaces",
            "layer": "observation",
            "current_sdk_support": "unsupported_or_unmapped",
            "inspect_behavior": "observe_only",
            "execution_behavior": "halt",
            "proof_semantics": "not_verified",
            "default_recommended_action": "reject_invalid",
            "watchlist_status": "implemented"
        },
        {
            "id": "aws_agentcore_payments",
            "name": "AWS AgentCore payments",
            "layer": "managed_platform",
            "current_sdk_support": "unsupported_or_unmapped",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "not_verified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "x402_bazaar_discovery",
            "name": "x402 Bazaar / Discovery",
            "layer": "discovery",
            "current_sdk_support": "unsupported_or_unmapped",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "not_verified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        },
        {
            "id": "openapi_multi_offer_discovery",
            "name": "OpenAPI / x-payment-info multi-offer discovery",
            "layer": "discovery",
            "current_sdk_support": "unsupported_or_unmapped",
            "inspect_behavior": "observe_only",
            "execution_behavior": "none",
            "proof_semantics": "not_verified",
            "default_recommended_action": "observe_only",
            "watchlist_status": "watch_only"
        }
    ]