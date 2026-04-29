import uuid
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import time

class ChallengeSource(str, Enum):
    STANDARD_X402 = "payment_required_header"  # PAYMENT-REQUIRED
    STANDARD_WWW = "www_authenticate"         # WWW-Authenticate (L402/MPP)
    LEGACY_CUSTOM = "legacy_custom_header"    # x-402-payment-required
    BODY_CHALLENGE = "body_challenge"         # JSON Body

class AttestationSource(str, Enum):
    SERVER_JWS = "server_attested"             # PAYMENT-RESPONSE 由来
    CLIENT_REPORTED = "self_reported"         # クライアント自己申告 (txHash 等)

# ==========================================
# v1.4 / v1.5 / v1.5.9: Trust, Outcome & Evidence Layer Models
# ==========================================

class TrustDecision(BaseModel):
    """支払い前の相手先信用評価結果"""
    is_trusted: bool
    reason: str = ""

class L402ExecutionReport(BaseModel):
    """L402 Delegate 実行後の詳細レポート"""
    delegate_source: str = "native"  # "native" | "lightninglabs"
    authorization_value: str
    preimage: Optional[str] = None
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    amount_sats: Optional[int] = None
    endpoint: Optional[str] = None
    payment_performed: bool = True
    cached_token_used: bool = False
    verification_status: str = "verified"
    raw_receipt_ref: Optional[dict] = None

class OutcomeSummary(BaseModel):
    """決済後の期待状態（Outcome）の評価結果"""
    is_success: bool
    observed_state: str = ""
    message: str = ""
    external_evidence: dict = Field(default_factory=dict)

class PaymentEvidenceRecord(BaseModel):
    """v1.5.1 Experimental: 支払い判断と結果の証跡レコード"""
    timestamp: float = Field(default_factory=time.time)
    session_id: str
    correlation_id: str
    target_url: str
    method: str
    scheme: Optional[str] = None
    asset: Optional[str] = None
    amount: Optional[float] = None
    trust_decision: Optional[TrustDecision] = None
    receipt_summary: Optional[dict] = None
    outcome: Optional[OutcomeSummary] = None
    error_message: Optional[str] = None
    # v1.5.8 Beta Update: Added field to track the origin of the navigation hint
    navigation_source: Optional[str] = None
    # v1.5.9 Update: セッション予算の永続化・復元用の消費USD記録（決済成功時のみ記録）
    session_spend_delta_usd: Optional[float] = None
    # --- 新規追加 (Widening) ---
    delegate_source: str = "native"
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    cached_token_used: bool = False
    payment_performed: bool = True

class ExecutionContext(BaseModel):
    """軽量な意図とセッションのコンテキスト"""
    intent_label: str = "default_intent"
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hints: dict = Field(default_factory=dict)
    # v1.5.1 Experimental: 明示的かつ型安全な Evidence 引き回し用フィールド
    past_evidence: Optional[List[PaymentEvidenceRecord]] = None
    # v1.5.9 Update: セッション予算が Evidence から復元済みかを示すフラグ（二重復元防止）
    session_budget_restored: bool = False

class ParsedChallenge(BaseModel):
    scheme: str
    network: str
    amount: float
    asset: str
    parameters: Dict[str, Any]
    source: ChallengeSource                    
    raw_header: Optional[str] = None
    # 💡 新規追加: MPP / Payment draft telemetry
    draft_shape: Optional[str] = None
    payment_method: Optional[str] = None
    payment_intent: Optional[str] = None
    request_b64_present: bool = False
    decoded_request_valid: bool = False

class TrustEvidence(BaseModel):
    """評価の根拠を束ねるコンテナ（Source-Agnostic）"""
    url: str
    challenge: ParsedChallenge
    host_metadata: dict = Field(default_factory=dict)
    agent_hints: dict = Field(default_factory=dict)

class ExecutionResult(BaseModel):
    response: dict
    final_url: str
    retry_count: int = 0
    settlement_receipt: Optional[Any] = None
    used_scheme: Optional[str] = None
    used_asset: Optional[str] = None
    verification_status: Optional[str] = None
    outcome: Optional[OutcomeSummary] = None
    # 💡 新規追加: 失敗時のテレメトリ伝播用
    credential_shape: Optional[str] = None
    failure_reason: Optional[str] = None

class EvidenceRepository:
    """v1.5.1 / v1.5.9 Experimental: Evidenceの保存と取得を行うための抽象インターフェース"""
    
    def export_evidence(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        pass

    def import_evidence(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return []

    # v1.5.9 Update: セッション全体（session_id ベース）の Evidence を取得する口
    def import_session_evidence(self, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return []

    async def export_evidence_async(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        self.export_evidence(record, context)

    async def import_evidence_async(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return self.import_evidence(target_url, context)

    # v1.5.9 Update: セッション全体の Evidence を非同期で取得する口
    async def import_session_evidence_async(self, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return self.import_session_evidence(context)

@dataclass
class PaymentPolicy:
    """
    エージェントの自律経済行動を制限するガードレール (Policy Layer)
    """
    # 💡 修正: "Payment" を許可リストに追加
    allowed_schemes: List[str] = field(default_factory=lambda: [
        "L402", "x402", "lnc-evm-relay", "lnc-evm-transfer", "lnc-solana-transfer", "MPP", "Payment", "exact"
    ])
    allowed_assets: List[str] = field(default_factory=lambda: ["SATS", "USDC", "JPYC"])
    max_spend_per_tx_usd: float = 5.0
    max_spend_per_session_usd: float = 10.0
    allowed_hosts: Optional[List[str]] = None
    blocked_hosts: List[str] = field(default_factory=list)
    _session_spent_usd: float = field(default=0.0, repr=False)

class SettlementReceipt(BaseModel):
    receipt_id: str
    scheme: str
    settled_amount: float
    asset: str
    network: str
    proof_reference: str
    receipt_token: Optional[str] = None
    verification_status: str = "verified"
    source: AttestationSource = AttestationSource.CLIENT_REPORTED
    # --- 新規追加 (Widening) ---
    delegate_source: str = "native"
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    cached_token_used: bool = False
    payment_performed: bool = True
    endpoint: Optional[str] = None

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"
    GRANT_CREDIT = "GRANT_CREDIT"

class SchemeType(str, Enum):
    # Standard Protocols
    l402 = "L402"
    mpp = "MPP"
    x402 = "x402"
    grant = "grant"
    faucet = "faucet"
    
    # LN Church Canonical Routings
    lnc_evm_relay = "lnc-evm-relay"
    lnc_evm_transfer = "lnc-evm-transfer"
    lnc_solana_transfer = "lnc-solana-transfer"
    
    # --- Legacy Aliases (DEPRECATED: Mapped to lnc-* equivalents internally) ---
    # @deprecated: Use lnc_evm_transfer instead.
    x402_direct = "x402-direct"
    # @deprecated: Use lnc_solana_transfer instead.
    x402_solana = "x402-solana"


class PaymentAuth(BaseModel):
    scheme: SchemeType
    proof: str
    chainId: Optional[str] = None # CAIP-2 ネットワーク識別子 (e.g. "eip155:137") を許容するため str に
    agentId: Optional[str] = None # lnc-solana-transfer の要件

# ==========================================
# 🧭 HATEOAS & Common Models
# ==========================================
class NextAction(BaseModel):
    instruction_for_agent: str
    method: str
    url: Optional[str] = None
    suggested_payload: Optional[Dict[str, Any]] = None
    suggested_headers: Optional[Dict[str, str]] = None

class HateoasErrorResponse(BaseModel):
    status: str
    error_code: str
    message: str
    reason: Optional[str] = None
    retryable: Optional[bool] = None
    next_action: Optional[NextAction] = None

class OmikujiReceipt(BaseModel):
    txHash: Optional[str] = None
    ritual: str
    timestamp: int
    paid: str
    AgentId: Optional[str] = None
    agentId: Optional[str] = None  
    verify_token: str
    probe_verified: Optional[bool] = False
    proof_class: Optional[str] = None

class AgentIdentity(BaseModel):
    status: str
    public_profile_url: str
    agent_id: Optional[str] = None

# ==========================================
# ⛩️ Phase 1: Omikuji Models
# ==========================================
class OmikujiResponse(BaseModel):
    status: str
    result: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

# ==========================================
# ⛩️ Phase 2: Confession & Hono Models
# ==========================================
class NormalizedInterpretation(BaseModel):
    failure_class: str
    constraint_class: str
    conflict_class: str
    recommended_next_action: str
    confidence: float

class FeedProjection(BaseModel):
    publishable: bool
    summary: str

class CanonicalSchema(BaseModel):
    schema_version: str
    event_summary: str
    normalized_interpretation: NormalizedInterpretation
    sanitized_evidence: List[str]
    feed_projection: FeedProjection

class ConfessionResponse(BaseModel):
    status: str
    confession_id: str
    recorded_schema: CanonicalSchema
    next_action: Optional[NextAction] = None

class HybridConfessionResponse(BaseModel):
    status: str
    oracle: str
    paid: float
    tier: str
    receiptId: str
    next_action: Optional[NextAction] = None

class HonoResponse(BaseModel):
    status: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

# ==========================================
# ⛩️ Phase 3: Benchmark & Trials Models
# ==========================================
class AggregateResponse(BaseModel):
    status: str
    message: str
    paid: str
    receipt_id: str
    next_action: Optional[NextAction] = None

class PerformanceStats(BaseModel):
    score: float
    latency_sec: float
    retry_count: float

class CompareAnalytics(BaseModel):
    critical_bottleneck: str
    advice: str

class CompareResponse(BaseModel):
    status: str
    trial_id: str
    paid: str
    receipt_id: str
    my_performance: PerformanceStats
    top_10_average: PerformanceStats
    analytics: CompareAnalytics

class BenchmarkOverviewResponse(BaseModel):
    status: str
    message: str
    benchmark: Dict[str, Any]
    next_action: Optional[NextAction] = None

# ==========================================
# ⛩️ Phase 4: Missionary Work (Monzen DNS) Models
# ==========================================
class MonzenTraceResponse(BaseModel):
    status: str
    action_type: str
    trace_id: str
    recorded_hash: str
    timestamp: int
    virtue_earned: int
    verification_status: Optional[str] = None
    verification_method: Optional[str] = None
    proof_reference: Optional[str] = None
    message: str
    # v1.5.8 Update: Changed from Optional[Dict[str, Any]] to Optional[NextAction]
    next_action: Optional[NextAction] = None

class SiteRanking(BaseModel):
    domain: str
    total_verifications: int
    unique_agents: int
    last_verified_at: int

class MonzenMetricsResponse(BaseModel):
    status: str
    tier: str
    limit_applied: int
    rankings: List[SiteRanking]
    next_action: Optional[NextAction] = None

class MonzenGraphResponse(BaseModel):
    status: str
    tier: str
    payment_scheme_used: str
    data: Dict[str, Any]
    next_action: Optional[NextAction] = None

# ==========================================
# 🔒 Internal Models (v1.6+ Access Selection)
# ==========================================
class _ExecutionUnlock(str, Enum):
    SETTLEMENT_PROOF = "settlement_proof"
    ENTITLEMENT_PROOF = "entitlement_proof"

class _FundingPolicy(str, Enum):
    SELF_FUNDED = "self_funded"
    SUBSIDIZED = "subsidized"
    FULLY_SPONSORED = "fully_sponsored"

class _EntitlementKind(str, Enum):
    FAUCET = "faucet"
    GRANT = "grant"

class _ExecutionAccessPlan(BaseModel):
    unlock: _ExecutionUnlock
    funding_policy: _FundingPolicy
    entitlement_kind: Optional[_EntitlementKind] = None
    settlement_scheme: str
    settlement_asset: str
    selected_reason: str = ""

# ==========================================
# 🧪 Sandbox & Interoperability Models
# ==========================================
class InteropRunResult(BaseModel):
    """Sandbox Harness の End-to-End 実行結果"""
    ok: bool
    target_url: str
    run_id: str
    scenario_id: str
    executor_mode: str
    delegate_source: str
    canonical_hash_expected: str
    canonical_hash_observed: str
    canonical_hash_matched: bool
    report_status_code: int
    report_accepted: bool
    payment_performed: bool
    cached_token_used: bool
    receipt_id: Optional[str] = None
    raw_report_response: Dict[str, Any]

# ==========================================
# 🧪 External Protocol Verification Models (New)
# ==========================================
class ExternalProtocolRunResult(BaseModel):
    """外部ライブエンドポイント向けのプロトコル実行結果 (Client-Attested)"""
    ok: bool
    target_url: str
    scenario_id: str
    verification_scope: str = "client_attested_external"
    comparison_basis: str = "protocol_success"
    executor_mode: str
    delegate_source: str
    status_code_after_payment: int
    payment_performed: bool
    cached_token_used: bool
    receipt_id: Optional[str] = None
    latency_ms: int
    response_shape_ok: bool
    response_excerpt: str
    protocol_success: bool
    schema_check_reason: str = ""
    error_stage: Optional[str] = None
    error_reason: Optional[str] = None
    # --- デバッグ・分析用フィールド追加 ---
    suspected_failure_origin: str = "unknown" # payment_backend | target_endpoint | local_env | unknown
    upstream_status_code: Optional[int] = None
    upstream_host_excerpt: Optional[str] = None
    debug_logs: List[str] = Field(default_factory=list)

