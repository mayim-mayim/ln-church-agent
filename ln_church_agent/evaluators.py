import requests
from urllib.parse import urlparse
from typing import Optional, Callable, Literal
from ln_church_agent.models import (
    TrustDecision, OutcomeSummary, TrustEvidence, ExecutionContext, SettlementReceipt
)

class RemoteTrustEvaluator:
    """
    LN Church API を 'Advisor (推奨者)' として参照し、
    ローカルポリシーと合成して 'Final Judge (最終決定)' を下す評価器。
    """
    def __init__(
        self,
        endpoint_url: str,
        timeout: float = 2.0,
        fallback_mode: Literal["allow_on_error", "strict", "allow_if_local_hint"] = "allow_on_error",
        prefer_remote_recommendation: bool = True
    ):
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.fallback_mode = fallback_mode
        self.prefer_remote_recommendation = prefer_remote_recommendation

    def __call__(self, evidence: TrustEvidence, context: ExecutionContext) -> TrustDecision:
        payload = {
            "target_url": evidence.url,
            "challenge": {
                "scheme": evidence.challenge.scheme,
                "network": evidence.challenge.network,
                "asset": evidence.challenge.asset,
                "amount": evidence.challenge.amount
            },
            "context": {
                "intent_label": context.intent_label,
                "session_id": context.session_id,
                "agent_id": context.hints.get("agent_id", "unknown"),
                "hints": evidence.agent_hints
            }
        }

        target_host = urlparse(evidence.url).netloc
        allowed_hosts = evidence.agent_hints.get("allowed_hosts", [])
        
        remote_recommendation = "unknown"
        remote_reason = ""
        evidence_bundle = {}
        remote_failed = False

        # ==========================================
        # 1. Ask the Advisor (リモートへの問い合わせ)
        # ==========================================
        try:
            res = requests.post(self.endpoint_url, json=payload, timeout=self.timeout)
            if res.ok:
                data = res.json()
                # v1.5.10: recommendation を優先、なければ古い decision を使用
                remote_recommendation = data.get("recommendation", data.get("decision", "unknown"))
                remote_reason = data.get("reason", "")
                evidence_bundle = data.get("evidence_bundle", {})
            else:
                remote_failed = True
                remote_reason = f"HTTP {res.status_code}"
        except Exception as e:
            remote_failed = True
            remote_reason = str(e)

        # 観測可能性(Observability)のため、アドバイスをコンテキストに保存
        context.hints["remote_trust_advice"] = {
            "recommendation": remote_recommendation,
            "evidence_bundle": evidence_bundle,
            "failed": remote_failed
        }

        # ==========================================
        # 2. Final Judge (ローカルポリシーとの合成)
        # ==========================================
        is_trusted = True
        final_reason = ""

        # [Rule A] Local Override (ローカルホワイトリストが最強)
        if allowed_hosts and target_host in allowed_hosts:
            is_trusted = True
            final_reason = f"[Local Override] Host {target_host} is in allowed_hosts. Ignored remote advice: {remote_recommendation}."
            return TrustDecision(is_trusted=is_trusted, reason=final_reason)

        # [Rule B] Remote Advice の採用
        if not remote_failed:
            if self.prefer_remote_recommendation:
                if remote_recommendation == "deny":
                    is_trusted = False
                    final_reason = f"[Remote Advisor] Blocked: {remote_reason}"
                elif remote_recommendation == "allow":
                    is_trusted = True
                    final_reason = f"[Remote Advisor] Allowed: {remote_reason}"
                else:
                    is_trusted = True 
                    final_reason = f"[Remote Advisor] Unknown status, defaulting to allow. Reason: {remote_reason}"
            else:
                is_trusted = remote_recommendation != "deny"
                final_reason = f"[Synthesized] Remote said {remote_recommendation}. {remote_reason}"

            return TrustDecision(is_trusted=is_trusted, reason=final_reason)

        # [Rule C] Local Fallback (リモート障害時)
        if self.fallback_mode == "strict":
            is_trusted = False
            final_reason = f"[Local Fallback: Strict] Blocked due to remote API failure ({remote_reason})."
        elif self.fallback_mode == "allow_if_local_hint":
            is_trusted = False
            final_reason = f"[Local Fallback: Hint Required] Blocked. Remote failed and host not in allowed_hosts."
        else:
            is_trusted = True
            final_reason = f"[Local Fallback: Allow On Error] Allowed despite remote API failure ({remote_reason})."

        return TrustDecision(is_trusted=is_trusted, reason=final_reason)


class RemoteOutcomeMatcher:
    """
    LN Church API を検証バックエンドの1つとして利用し、
    ローカルの構造検証と合成して最終的な OutcomeSummary を決定する検証器。
    """
    def __init__(
        self, 
        endpoint_url: str, 
        timeout: float = 2.0, 
        local_fallback_matcher: Optional[Callable] = None
    ):
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.local_fallback_matcher = local_fallback_matcher

    def __call__(self, response: dict, receipt: Optional[SettlementReceipt], context: ExecutionContext) -> OutcomeSummary:
        preview = {}
        if isinstance(response, dict):
            preview = {
                "status": response.get("status"),
                "tier": response.get("tier"),
                "payment_scheme_used": response.get("payment_scheme_used"),
                "data_shape": {
                    "has_data": "data" in response,
                    "has_error": "error" in response,
                    "has_nodes": "nodes" in response.get("data", {}),
                    "has_links": "links" in response.get("data", {})
                }
            }

        payload = {
            "target_url": context.hints.get("target_url", "unknown"),
            "intent_label": context.intent_label,
            "settlement": {
                "receipt_id": receipt.receipt_id if receipt else None,
                "scheme": receipt.scheme if receipt else None,
                "asset": receipt.asset if receipt else None,
                "settled_amount": receipt.settled_amount if receipt else 0.0,
                "proof_reference": receipt.proof_reference if receipt else None
            },
            "response": {
                "status_code": 200,
                "body_preview": preview
            },
            "context": {
                "agent_id": context.hints.get("agent_id", "unknown")
            }
        }

        remote_success = None
        remote_checks = {}
        evidence_bundle = {}
        remote_state = "unverified"
        remote_msg = ""
        remote_failed = False

        # ==========================================
        # 1. Ask the Advisor (リモートへの問い合わせ)
        # ==========================================
        try:
            res = requests.post(self.endpoint_url, json=payload, timeout=self.timeout)
            if res.ok:
                data = res.json()
                remote_success = data.get("recommended_success", data.get("is_success"))
                remote_checks = data.get("checks", {})
                evidence_bundle = data.get("evidence_bundle", {})
                remote_state = data.get("observed_state", "unverified")
                remote_msg = data.get("reason", "")
            else:
                remote_failed = True
                remote_msg = f"HTTP {res.status_code}"
        except Exception as e:
            remote_failed = True
            remote_msg = str(e)

        external_evidence = {
            "remote_checks": remote_checks,
            "evidence_bundle": evidence_bundle,
            "remote_failed": remote_failed
        }

        # ==========================================
        # 2. Final Judge (ローカル検証器との合成)
        # ==========================================
        
        # [Rule A] ユーザー定義の Local Fallback Matcher があれば最優先で評価
        if self.local_fallback_matcher:
            local_outcome = self.local_fallback_matcher(response, receipt, context)
            
            # リモートが収集した証拠を external_evidence として合流させる
            merged_evidence = {**(local_outcome.external_evidence or {}), **external_evidence}
            
            return OutcomeSummary(
                is_success=local_outcome.is_success,
                observed_state=local_outcome.observed_state or remote_state,
                message=f"[Local Matcher Override] {local_outcome.message}. (Remote advice: {remote_success})",
                external_evidence=merged_evidence
            )

        # [Rule B] Remote Advice の採用
        if not remote_failed and remote_success is not None:
            return OutcomeSummary(
                is_success=remote_success,
                observed_state=remote_state,
                message=f"[Remote Advisor] {remote_msg}",
                external_evidence=external_evidence
            )

        # [Rule C] Generic Structural Fallback (リモート障害時・専用Matcher未定義時)
        # 決済は成功しているので、明らかなエラー文字がなければ成功とみなす
        is_success = isinstance(response, dict) and "error" not in response and response.get("status") != "error"
        return OutcomeSummary(
            is_success=is_success,
            observed_state="unverified_local_fallback",
            message=f"[Local Fallback] Remote verification failed ({remote_msg}). Used generic structural check.",
            external_evidence=external_evidence
        )