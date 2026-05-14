import hashlib
import json
import time
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from .models import PaymentFailureRecord

# Taxonomy
FAILURE_CLASSES = {
    "unattempted", "parse_failed", "unsupported_challenge_shape", "policy_blocked",
    "payment_payload_build_failed", "signing_failed", "settlement_submission_failed",
    "retry_mismatch", "counterparty_rejected_payment", "network_or_transport_error", 
    "timeout", "unknown_server_behavior", "client_internal_error",
    "post_settlement_proof_required", "receipt_verification_failed", "outcome_mismatch"
}

FAILURE_SUBCLASSES = {
    "no_matching_payment_requirements",
    "fee_payer_changed",
    "payment_requirements_changed",
    "invalid_payment_payload",
    "missing_receipt",
    "receipt_rejected",
    "semantic_outcome_failed"
}

SECRET_KEYS = {
    "authorization", "www-authenticate", "payment-signature", "payment-response",
    "macaroon", "preimage", "private_key", "grant_token", "mandate_token",
    "shared_payment_token", "access_token", "refresh_token", "secret", "api_key",
    "signature", "proof"
}

def _redact_message(msg: Optional[str]) -> Optional[str]:
    if not msg:
        return msg
    
    # ターゲットとなるキーを正規表現の OR で結合
    keys_pattern = "|".join(re.escape(k) for k in SECRET_KEYS)
    
    # \b: 単語境界 (authorization_scheme 等を巻き込まないため)
    # \s*[:=]?\s*: key: value, key=value, key value の区切り文字
    # [\'"]?(?:Bearer\s+)?[a-zA-Z0-9\-\._~+/=]+[\'"]?: 値部分 (Bearerプレフィックスや引用符、Base64/Hex文字を許容)
    pattern = re.compile(
        r'\b(?:' + keys_pattern + r')\b\s*[:=]?\s*[\'"]?(?:Bearer\s+)?[a-zA-Z0-9\-\._~+/=]+[\'"]?',
        re.IGNORECASE
    )
    
    redacted = pattern.sub("[REDACTED]", msg)
    return redacted[:300]

def fingerprint_public_challenge_summary(obj: Any) -> str:
    """秘匿情報を除外して構造の指紋を生成する (List 対応)"""
    def _sanitize(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _sanitize(v) for k, v in o.items() if str(k).lower() not in SECRET_KEYS}
        elif isinstance(o, list):
            return [_sanitize(item) for item in o]
        return o

    safe_obj = _sanitize(obj)
    dump = json.dumps(safe_obj, sort_keys=True)
    return hashlib.sha256(dump.encode()).hexdigest()[:16]

def detect_public_challenge_changed_fields(before: Any, after: Any, prefix: str = "") -> List[str]:
    """チャレンジ間の差分フィールド名を抽出する (List/ネスト対応)"""
    changed = []
    if isinstance(before, dict) and isinstance(after, dict):
        for k in set(before.keys()) | set(after.keys()):
            if str(k).lower() in SECRET_KEYS: continue
            path = f"{prefix}{k}"
            vb = before.get(k)
            va = after.get(k)
            if vb != va:
                if isinstance(vb, (dict, list)) and isinstance(va, (dict, list)):
                    changed.extend(detect_public_challenge_changed_fields(vb, va, f"{path}."))
                else:
                    changed.append(path)
    elif isinstance(before, list) and isinstance(after, list):
        for i in range(max(len(before), len(after))):
            path = f"{prefix[:-1]}[{i}]" if prefix else f"[{i}]"
            if i >= len(before) or i >= len(after):
                changed.append(path)
            elif before[i] != after[i]:
                if isinstance(before[i], (dict, list)) and isinstance(after[i], (dict, list)):
                    changed.extend(detect_public_challenge_changed_fields(before[i], after[i], f"{path}."))
                else:
                    changed.append(path)
    else:
        if before != after and prefix:
            changed.append(prefix.rstrip("."))
            
    return sorted(list(set(changed)))[:20]

def build_payment_failure_record(
    endpoint: str,
    method: str = "GET",
    rail: str = "unknown",
    scheme: Optional[str] = None,
    network: str = "unknown",
    asset: str = "unknown",
    authorization_scheme: Optional[str] = None,
    draft_shape: Optional[str] = None,
    payment_intent: Optional[str] = None,
    failure_class: str = "unknown_server_behavior",
    failure_subclass: Optional[str] = None,
    final_http_status: Optional[int] = None,
    server_message: Optional[str] = None,
    client_error: Optional[str] = None,
    client_used: str = "ln-church-agent",
    secondary_client_used: Optional[str] = None,
    challenge_before: Optional[Any] = None,
    challenge_after: Optional[Any] = None,
    selected_requirement: Optional[Any] = None,
    error_stage: Optional[str] = None,
    attempted: bool = True,
    attempt_count: int = 1,
    retry_count: int = 0,
    operator_verified: bool = False,
    payment_performed: bool = False,
    settlement_confirmed: bool = False,
    payment_receipt_present: bool = False,
    public_notes: Optional[str] = None,
    **kwargs
) -> PaymentFailureRecord:
    
    observed_at = int(time.time())
    before = challenge_before or {}
    after = challenge_after or {}
    
    fp_b = fingerprint_public_challenge_summary(before) if before else None
    fp_a = fingerprint_public_challenge_summary(after) if after else None
    fp_req = fingerprint_public_challenge_summary(selected_requirement) if selected_requirement else None
    changed = detect_public_challenge_changed_fields(before, after) if (before and after) else []
    
    if failure_subclass == "no_matching_payment_requirements":
        failure_class = "retry_mismatch"

    repro = "single_client_observed"
    strength = "low"
    if secondary_client_used:
        repro = "dual_client_reproduced"
        strength = "medium"
    if operator_verified:
        repro = "operator_verified"
        strength = "high"

    # IDの安定化 (day_bucket使用)
    day_bucket = time.strftime("%Y-%m-%d", time.gmtime(observed_at))
    seed = f"{endpoint}|{rail}|{failure_class}|{failure_subclass}|{fp_b}|{fp_a}|{day_bucket}"
    rec_id = "fail_" + hashlib.sha256(seed.encode()).hexdigest()[:16]
    
    safe_server_msg = _redact_message(server_message)[:300] if server_message else None
    safe_client_err = _redact_message(client_error)[:300] if client_error else None

    # kwargsフィルタリング
    base_data = {k: v for k, v in kwargs.items() if k in PaymentFailureRecord.model_fields}

    return PaymentFailureRecord(
        record_id=rec_id,
        observed_at=observed_at,
        endpoint=endpoint,
        target_domain=urlparse(endpoint).netloc,
        method=method,
        rail=rail,
        scheme=scheme,
        network=network,
        asset=asset,
        authorization_scheme=authorization_scheme,
        draft_shape=draft_shape,
        payment_intent=payment_intent,
        challenge_fingerprint_before=fp_b,
        challenge_fingerprint_after=fp_a,
        challenge_fingerprint_changed=bool(changed),
        changed_fields=changed,
        selected_requirement_fingerprint=fp_req,
        attempted=attempted,
        attempt_count=attempt_count,
        retry_count=retry_count,
        client_used=client_used,
        secondary_client_used=secondary_client_used,
        final_http_status=final_http_status,
        failure_class=failure_class,
        failure_subclass=failure_subclass,
        error_stage=error_stage,
        server_message_excerpt=safe_server_msg,
        client_error_excerpt=safe_client_err,
        reproducibility=repro,
        evidence_strength=strength,
        confidence=strength,
        operator_verified=operator_verified,
        payment_performed=payment_performed,
        settlement_confirmed=settlement_confirmed,
        payment_receipt_present=payment_receipt_present,
        public_notes=public_notes,
        safe_to_publish=True,
        redaction_applied=True,
        **base_data
    )

def build_payment_failure_observation_payload(record: PaymentFailureRecord, agent_id: str = "optional-agent-id") -> dict:
    return {
        "schema_version": "payment_failure_observation_report.v1",
        "observation_type": "payment_failure",
        "source_channel": "agent_sdk",
        "source_scope": "external_agent_report",
        "agentId": agent_id,
        "targetUrl": record.endpoint,
        "targetDomain": record.target_domain,
        "method": record.method,
        "protocol": {
            "rail": record.rail, 
            "scheme": record.scheme or "unknown",
            "network": record.network, 
            "asset": record.asset,
            "authorization_scheme": record.authorization_scheme or record.rail or "unknown",
            "draft_shape": record.draft_shape or "unknown",
            "payment_intent": record.payment_intent or "unknown"
        },
        "failure": {
            "failure_class": record.failure_class,
            "failure_subclass": record.failure_subclass,
            "error_stage": record.error_stage,
            "attempted": record.attempted,
            "attempt_count": record.attempt_count,
            "retry_count": record.retry_count,
            "final_http_status": record.final_http_status,
            "server_message_excerpt": record.server_message_excerpt,
            "client_error_excerpt": record.client_error_excerpt,
            "challenge_fingerprint_changed": record.challenge_fingerprint_changed,
            "changed_fields": record.changed_fields
        },
        "evidence": {
            "reproducibility": record.reproducibility,
            "evidence_strength": record.evidence_strength,
            "confidence": record.confidence,
            "operator_verified": record.operator_verified,
            "payment_performed": record.payment_performed,
            "settlement_confirmed": record.settlement_confirmed,
            "payment_receipt_present": record.payment_receipt_present,
            "redaction_applied": record.redaction_applied
        },
        "client": {
            "client_used": record.client_used,
            "secondary_client_used": record.secondary_client_used,
            "sdk_version": "1.9.4"
        },
        "public_statement": "A payment attempt against this endpoint was observed to fail under this client/runtime condition.",
        "not_a_verdict": True
    }